//! Bounded, passive inspection of QUIC v1/v2 client Initial packets.
//!
//! This module authenticates and inspects Initial packets and can validate one
//! server Retry transition. It deliberately does not implement a UDP listener,
//! general connection tracking, or relay.

use std::collections::HashSet;

use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use rustls::{
    Side,
    quic::{HeaderProtectionKey, PacketKey},
};
use thiserror::Error;

use super::tls::{TlsInspectError, parse_client_hello};

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const MIN_INITIAL_DATAGRAM_LEN: usize = 1200;
const MAX_CONNECTION_ID_LEN: usize = 20;
const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;
const CLIENT_HELLO_TYPE: u8 = 1;
const HANDSHAKE_HEADER_LEN: usize = 4;
const RETRY_INTEGRITY_TAG_LEN: usize = 16;
const V1_RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const V1_RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const V2_RETRY_KEY: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const V2_RETRY_NONCE: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// QUIC versions whose Initial cryptography is supported by the inspector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    fn from_wire(value: u32) -> Result<Self, QuicInspectError> {
        match value {
            QUIC_V1 => Ok(Self::V1),
            QUIC_V2 => Ok(Self::V2),
            other => Err(QuicInspectError::UnsupportedVersion(other)),
        }
    }

    fn rustls(self) -> rustls::quic::Version {
        match self {
            Self::V1 => rustls::quic::Version::V1,
            Self::V2 => rustls::quic::Version::V2,
        }
    }

    /// Return the final wire codepoint for this supported QUIC version.
    #[must_use]
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => QUIC_V1,
            Self::V2 => QUIC_V2,
        }
    }
}

/// Unprotected fields needed to establish a bounded runtime inspection state.
///
/// This is not a routing result. A caller must still authenticate and inspect
/// the packet with [`QuicInitialInspector`] before DNS or upstream I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicClientInitialHeader {
    pub version: QuicVersion,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
}

/// Structurally visible type of a supported-version long-header packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicLongHeaderKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// Unprotected identity fields from the first supported-version long-header
/// packet in a datagram. This is never a routing or authentication result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicLongHeader {
    pub version: QuicVersion,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub kind: QuicLongHeaderKind,
}

/// Parse the first supported-version long-header packet without trusting its
/// protected payload.
///
/// # Errors
///
/// Returns an error for a short/fixed-bit header violation, unsupported
/// version, malformed connection IDs, or truncated packet framing.
pub fn parse_client_long_header(datagram: &[u8]) -> Result<QuicLongHeader, QuicInspectError> {
    let first = datagram
        .first()
        .copied()
        .ok_or(QuicInspectError::Malformed {
            reason: "empty client datagram",
        })?;
    if first & 0x80 == 0 || first & 0x40 == 0 {
        return malformed("first packet does not have a valid long header");
    }
    let packet = parse_long_packet(datagram, 0)?;
    let kind = match packet.kind {
        LongPacketKind::Initial => QuicLongHeaderKind::Initial,
        LongPacketKind::ZeroRtt => QuicLongHeaderKind::ZeroRtt,
        LongPacketKind::Handshake => QuicLongHeaderKind::Handshake,
        LongPacketKind::Retry => QuicLongHeaderKind::Retry,
    };
    Ok(QuicLongHeader {
        version: packet.version,
        destination_connection_id: packet.dcid,
        source_connection_id: packet.scid,
        kind,
    })
}

/// Validate the visible connection identity of every coalesced client
/// long-header packet in one datagram.
///
/// This is structural validation only. It is suitable after a tuple has
/// already authenticated an Initial destination and been pinned to one
/// upstream. Client Retry packets are rejected, and parsing stops at a short
/// header because its connection-ID length is not self-describing.
///
/// # Errors
///
/// Returns an error for malformed framing, Retry, or a version/DCID/SCID that
/// differs from the active session identity.
pub fn validate_client_long_header_datagram_identity(
    datagram: &[u8],
    expected_version: u32,
    expected_destination_connection_id: &[u8],
    expected_source_connection_id: &[u8],
) -> Result<(), QuicInspectError> {
    let mut offset = 0usize;
    while offset < datagram.len() {
        let first = datagram[offset];
        if first & 0x80 == 0 {
            break;
        }
        if first & 0x40 == 0 {
            return malformed("client long header has a cleared fixed bit");
        }
        let packet = parse_long_packet(datagram, offset)?;
        if packet.kind == LongPacketKind::Retry {
            return malformed("client datagram contains a Retry packet");
        }
        if packet.version.wire() != expected_version
            || packet.dcid != expected_destination_connection_id
            || packet.scid != expected_source_connection_id
        {
            return malformed("client long-header identity differs from the active session");
        }
        offset = packet.end;
    }
    Ok(())
}

/// Learn the source connection ID advertised by server Initial packets in one
/// structurally valid, supported-version datagram.
///
/// This helper does not authenticate the server Initial payload. Runtime
/// callers must invoke it only for a datagram received from an already
/// connected and policy-pinned upstream socket. Every coalesced long-header
/// packet is framed, every version must match `expected_version`, and all
/// server Initial packets in the datagram must advertise one stable SCID.
/// Short-header data terminates parsing because it cannot be framed without
/// the negotiated connection-ID length.
///
/// # Errors
///
/// Returns an error for malformed long-header framing, a version mismatch, or
/// conflicting server Initial SCIDs in the same datagram.
pub fn parse_server_initial_source_connection_id(
    datagram: &[u8],
    expected_version: u32,
    expected_destination_connection_id: &[u8],
) -> Result<Option<Vec<u8>>, QuicInspectError> {
    let mut offset = 0usize;
    let mut source_connection_id = None;
    let mut contains_initial = false;
    while offset < datagram.len() {
        let first = datagram[offset];
        if first & 0x80 == 0 {
            break;
        }
        if first & 0x40 == 0 {
            return malformed("server long header has a cleared fixed bit");
        }
        let packet = parse_long_packet(datagram, offset)?;
        if packet.version.wire() != expected_version {
            return malformed("server long-header version changed within the session");
        }
        if packet.dcid != expected_destination_connection_id {
            return malformed("server long-header DCID differs from the client Initial SCID");
        }
        offset = packet.end;
        match &source_connection_id {
            Some(previous) if previous != &packet.scid => {
                return malformed("coalesced server long-header packets use conflicting SCIDs");
            }
            Some(_) => {}
            None => source_connection_id = Some(packet.scid),
        }
        contains_initial |= packet.kind == LongPacketKind::Initial;
    }
    if contains_initial {
        Ok(source_connection_id)
    } else {
        Ok(None)
    }
}

/// Parse the first packet as a supported client Initial without trusting its
/// protected contents.
///
/// # Errors
///
/// Returns an error for unsupported versions, non-Initial first packets,
/// malformed headers, invalid connection IDs, or a datagram shorter than the
/// QUIC Initial minimum. Successful parsing is only suitable for indexing an
/// inspection attempt; it does not authenticate a destination.
pub fn parse_client_initial_header(
    datagram: &[u8],
) -> Result<QuicClientInitialHeader, QuicInspectError> {
    if datagram.len() < MIN_INITIAL_DATAGRAM_LEN {
        return malformed("client Initial datagram is shorter than 1200 bytes");
    }
    let packet = parse_client_long_header(datagram)?;
    if packet.kind != QuicLongHeaderKind::Initial {
        return malformed("first packet is not a client Initial");
    }
    if packet.destination_connection_id.len() < 8 {
        return malformed("first client Initial DCID is shorter than 8 bytes");
    }
    Ok(QuicClientInitialHeader {
        version: packet.version,
        destination_connection_id: packet.destination_connection_id,
        source_connection_id: packet.source_connection_id,
    })
}

/// Hard limits for one passive Initial inspection attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicInspectConfig {
    pub max_crypto_bytes: usize,
    pub max_datagram_bytes: usize,
    pub max_total_datagram_bytes: usize,
    pub max_datagrams: usize,
    pub max_initial_packets: usize,
    pub max_frames_per_packet: usize,
    pub max_ack_ranges: usize,
}

impl Default for QuicInspectConfig {
    fn default() -> Self {
        Self {
            max_crypto_bytes: 64 * 1024,
            max_datagram_bytes: 65_535,
            max_total_datagram_bytes: 512 * 1024,
            max_datagrams: 64,
            max_initial_packets: 128,
            max_frames_per_packet: 256,
            max_ack_ranges: 64,
        }
    }
}

/// A destination authenticated from a complete TLS `ClientHello` in QUIC CRYPTO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInspection {
    pub server_name: String,
    pub version: QuicVersion,
    /// DCID used to derive the authenticated client Initial keys.
    pub destination_connection_id: Vec<u8>,
}

/// Authenticated state carried from a server Retry into later client Initials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicRetry {
    pub version: QuicVersion,
    pub original_destination_connection_id: Vec<u8>,
    pub retry_source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
}

/// Whether a structurally selected Retry created a transition or repeated the
/// already authenticated transition exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicRetryAcceptance {
    New(QuicRetry),
    Duplicate(QuicRetry),
}

#[derive(Debug, Error)]
pub enum QuicInspectError {
    #[error("invalid QUIC inspection configuration: {reason}")]
    InvalidConfig { reason: &'static str },
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedVersion(u32),
    #[error("malformed QUIC Initial: {reason}")]
    Malformed { reason: &'static str },
    #[error("QUIC packet authentication failed")]
    AuthenticationFailed,
    #[error("QUIC resource limit exceeded: {resource} (limit {limit})")]
    ResourceLimit {
        resource: &'static str,
        limit: usize,
    },
    #[error("frame type {frame_type:#x} is forbidden in a QUIC Initial packet")]
    ForbiddenFrame { frame_type: u64 },
    #[error("TLS ClientHello carried by QUIC is unroutable: {0}")]
    Tls(#[from] TlsInspectError),
    #[error("QUIC inspection already completed")]
    AlreadyCompleted,
}

/// Stateful reassembly for a single, pre-Relay client Initial flight.
pub struct QuicInitialInspector {
    config: QuicInspectConfig,
    initial: Option<InitialKeys>,
    crypto: CryptoReassembly,
    datagrams: usize,
    total_datagram_bytes: usize,
    initial_packets: usize,
    original_destination_connection_id: Option<Vec<u8>>,
    client_source_connection_id: Option<Vec<u8>>,
    retry: Option<QuicRetry>,
    completed: bool,
}

impl QuicInitialInspector {
    /// Create an inspector after validating every configured bound.
    ///
    /// # Errors
    ///
    /// Returns [`QuicInspectError::InvalidConfig`] for zero or inconsistent
    /// limits.
    pub fn new(config: QuicInspectConfig) -> Result<Self, QuicInspectError> {
        validate_config(config)?;
        Ok(Self {
            config,
            initial: None,
            crypto: CryptoReassembly::default(),
            datagrams: 0,
            total_datagram_bytes: 0,
            initial_packets: 0,
            original_destination_connection_id: None,
            client_source_connection_id: None,
            retry: None,
            completed: false,
        })
    }

    /// Authenticate and accept one server Retry packet for this Initial flight.
    ///
    /// The inspector must first authenticate at least one client Initial. The
    /// packet is checked against the retained original DCID and client SCID.
    /// Later client Initials must use the Retry SCID as DCID, repeat the exact
    /// token, and retain the client's original SCID.
    ///
    /// # Errors
    ///
    /// An exact authenticated retransmission is idempotent. A changed Retry,
    /// invalid integrity tag, mismatched connection ID/version, empty token,
    /// malformed wire data, or bound violation fails closed.
    pub fn accept_retry(&mut self, retry_packet: &[u8]) -> Result<QuicRetry, QuicInspectError> {
        self.account_datagram(retry_packet.len())?;
        let first = retry_packet
            .first()
            .copied()
            .ok_or(QuicInspectError::Malformed {
                reason: "empty Retry packet",
            })?;
        if first & 0x80 == 0 || first & 0x40 == 0 {
            return malformed("Retry does not have a valid long header");
        }
        let packet = parse_long_packet(retry_packet, 0)?;
        if packet.kind != LongPacketKind::Retry
            || packet.start != 0
            || packet.end != retry_packet.len()
        {
            return malformed("server packet is not exactly one Retry packet");
        }

        let initial = self.initial.as_ref().ok_or(QuicInspectError::Malformed {
            reason: "Retry arrived before an authenticated client Initial",
        })?;
        let original_dcid = self.original_destination_connection_id.as_ref().ok_or(
            QuicInspectError::Malformed {
                reason: "original client DCID was not retained",
            },
        )?;
        let client_scid =
            self.client_source_connection_id
                .as_ref()
                .ok_or(QuicInspectError::Malformed {
                    reason: "original client SCID was not retained",
                })?;
        if packet.version != initial.version {
            return malformed("Retry version differs from the client Initial version");
        }
        if packet.dcid != *client_scid {
            return malformed("Retry DCID differs from the client Initial SCID");
        }
        if packet.scid == *original_dcid {
            return malformed("Retry SCID repeats the original client DCID");
        }
        if packet.token.is_empty() {
            return malformed("Retry token is empty");
        }
        authenticate_retry(packet.version, original_dcid, retry_packet)?;

        let accepted = QuicRetry {
            version: packet.version,
            original_destination_connection_id: original_dcid.clone(),
            retry_source_connection_id: packet.scid.clone(),
            token: packet.token,
        };
        if let Some(previous) = &self.retry {
            if previous == &accepted {
                return Ok(accepted);
            }
            return malformed("server changed an already authenticated Retry transition");
        }
        let previous = self.initial.take().ok_or(QuicInspectError::Malformed {
            reason: "authenticated Initial keys disappeared during Retry",
        })?;
        self.initial = Some(previous.after_retry(accepted.retry_source_connection_id.clone())?);
        self.retry = Some(accepted.clone());
        // Retry starts a fresh Initial flight. Retain attempt-wide byte/packet
        // bounds and the packet-number floor, but require the retransmitted
        // ClientHello to authenticate and reassemble from scratch.
        self.crypto = CryptoReassembly::default();
        self.completed = false;
        Ok(accepted)
    }

    /// Authenticate a server Retry when the datagram structurally carries one.
    ///
    /// Ordinary server datagrams return `Ok(None)` without changing inspection
    /// state. A supported-version datagram whose long-header type is Retry is
    /// passed through the full integrity and connection-ID checks in
    /// [`Self::accept_retry`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::accept_retry`] for a malformed,
    /// unauthenticated, mismatched, or repeated Retry candidate.
    pub fn accept_retry_if_present(
        &mut self,
        datagram: &[u8],
    ) -> Result<Option<QuicRetryAcceptance>, QuicInspectError> {
        let Some(first) = datagram.first().copied() else {
            return Ok(None);
        };
        if first & 0xc0 != 0xc0 {
            return Ok(None);
        }
        let Some(version) = datagram
            .get(1..5)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes)
        else {
            return Ok(None);
        };
        let retry_type = match version {
            QUIC_V1 => 3,
            QUIC_V2 => 0,
            _ => return Ok(None),
        };
        if (first >> 4) & 0x03 != retry_type {
            return Ok(None);
        }
        let duplicate = self.retry.is_some();
        self.accept_retry(datagram).map(|retry| {
            Some(if duplicate {
                QuicRetryAcceptance::Duplicate(retry)
            } else {
                QuicRetryAcceptance::New(retry)
            })
        })
    }

    /// Authenticate Initial packets in one UDP datagram and reassemble CRYPTO.
    ///
    /// The caller must enforce an overall wall-clock timeout. `Ok(None)` means
    /// that the bounded `ClientHello` is not complete yet. Original datagrams are
    /// never retained or rewritten by this inspector.
    ///
    /// # Errors
    ///
    /// Fails closed on unsupported versions, malformed wire data, AEAD failure,
    /// forbidden Initial frames, conflicting CRYPTO overlap, TLS/ECH ambiguity,
    /// or any configured limit.
    pub fn inspect_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Option<QuicInspection>, QuicInspectError> {
        if self.completed {
            return Err(QuicInspectError::AlreadyCompleted);
        }
        self.account_datagram(datagram.len())?;

        let mut offset = 0usize;
        while offset < datagram.len() {
            let first = datagram[offset];
            if first & 0x80 == 0 {
                break;
            }
            if first & 0x40 == 0 {
                return malformed("long header has a cleared fixed bit");
            }

            let packet = parse_long_packet(datagram, offset)?;
            offset = packet.end;

            if packet.kind != LongPacketKind::Initial {
                if packet.kind == LongPacketKind::Retry {
                    return malformed("client datagram contains a Retry packet");
                }
                if packet.kind == LongPacketKind::ZeroRtt {
                    let initial = self.initial.as_ref().ok_or(QuicInspectError::Malformed {
                        reason: "0-RTT arrived before an authenticated client Initial",
                    })?;
                    let client_scid = self.client_source_connection_id.as_ref().ok_or(
                        QuicInspectError::Malformed {
                            reason: "client SCID state is missing",
                        },
                    )?;
                    if packet.version != initial.version
                        || packet.dcid != initial.dcid
                        || packet.scid != *client_scid
                    {
                        return malformed("0-RTT identity differs from the active Initial flight");
                    }
                }
                continue;
            }
            if datagram.len() < MIN_INITIAL_DATAGRAM_LEN {
                return malformed("client Initial datagram is shorter than 1200 bytes");
            }
            self.account_initial_packet()?;

            let plaintext = self.decrypt_initial(datagram, &packet)?;
            let Some(plaintext) = plaintext else {
                continue;
            };
            parse_initial_frames(&plaintext, &mut self.crypto, self.config)?;

            if let Some(server_name) = self.crypto.client_hello(self.config.max_crypto_bytes)? {
                let initial = self.initial.as_ref().ok_or(QuicInspectError::Malformed {
                    reason: "authenticated Initial state was not retained",
                })?;
                let version = initial.version;
                let destination_connection_id = initial.dcid.clone();
                self.completed = true;
                // The routing result is owned by the caller. Keep only the
                // compact key/CID state needed to authenticate a possible
                // Retry, not the potentially large completed CRYPTO flight.
                self.crypto = CryptoReassembly::default();
                return Ok(Some(QuicInspection {
                    server_name,
                    version,
                    destination_connection_id,
                }));
            }
        }

        Ok(None)
    }

    fn account_datagram(&mut self, len: usize) -> Result<(), QuicInspectError> {
        if len > self.config.max_datagram_bytes {
            return resource_limit("datagram bytes", self.config.max_datagram_bytes);
        }
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(QuicInspectError::ResourceLimit {
                resource: "datagrams",
                limit: self.config.max_datagrams,
            })?;
        if self.datagrams > self.config.max_datagrams {
            return resource_limit("datagrams", self.config.max_datagrams);
        }
        self.total_datagram_bytes =
            self.total_datagram_bytes
                .checked_add(len)
                .ok_or(QuicInspectError::ResourceLimit {
                    resource: "total datagram bytes",
                    limit: self.config.max_total_datagram_bytes,
                })?;
        if self.total_datagram_bytes > self.config.max_total_datagram_bytes {
            return resource_limit("total datagram bytes", self.config.max_total_datagram_bytes);
        }
        Ok(())
    }

    fn account_initial_packet(&mut self) -> Result<(), QuicInspectError> {
        self.initial_packets =
            self.initial_packets
                .checked_add(1)
                .ok_or(QuicInspectError::ResourceLimit {
                    resource: "Initial packets",
                    limit: self.config.max_initial_packets,
                })?;
        if self.initial_packets > self.config.max_initial_packets {
            return resource_limit("Initial packets", self.config.max_initial_packets);
        }
        Ok(())
    }

    fn decrypt_initial(
        &mut self,
        datagram: &[u8],
        packet: &ParsedLongPacket,
    ) -> Result<Option<Vec<u8>>, QuicInspectError> {
        let packet_bytes = &datagram[packet.start..packet.end];
        let pn_offset = packet.pn_offset - packet.start;

        if let Some(initial) = self.initial.as_mut() {
            if initial.version != packet.version || initial.dcid != packet.dcid {
                return malformed("Initial version or DCID does not match current Initial keys");
            }
            let expected_scid =
                self.client_source_connection_id
                    .as_ref()
                    .ok_or(QuicInspectError::Malformed {
                        reason: "client SCID state is missing",
                    })?;
            if packet.scid != *expected_scid {
                return malformed("client changed its SCID during the Initial flight");
            }
            if let Some(retry) = &self.retry
                && packet.token != retry.token
            {
                return malformed("client Initial did not repeat the Retry token");
            }
            return initial.decrypt(packet_bytes, pn_offset);
        }

        if packet.dcid.len() < 8 {
            return malformed("first client Initial DCID is shorter than 8 bytes");
        }
        let mut candidate = InitialKeys::new(packet.version, packet.dcid.clone())?;
        let plaintext = candidate.decrypt(packet_bytes, pn_offset)?;
        self.original_destination_connection_id = Some(packet.dcid.clone());
        self.client_source_connection_id = Some(packet.scid.clone());
        self.initial = Some(candidate);
        Ok(plaintext)
    }
}

fn validate_config(config: QuicInspectConfig) -> Result<(), QuicInspectError> {
    if config.max_crypto_bytes < HANDSHAKE_HEADER_LEN {
        return invalid_config("max_crypto_bytes must be at least 4");
    }
    if config.max_crypto_bytes > 0x0100_0003 {
        return invalid_config("max_crypto_bytes exceeds the TLS u24 message bound");
    }
    if !(MIN_INITIAL_DATAGRAM_LEN..=65_535).contains(&config.max_datagram_bytes) {
        return invalid_config("max_datagram_bytes must be between 1200 and 65535");
    }
    if config.max_total_datagram_bytes < config.max_datagram_bytes {
        return invalid_config("max_total_datagram_bytes is smaller than max_datagram_bytes");
    }
    if config.max_datagrams == 0
        || config.max_initial_packets == 0
        || config.max_frames_per_packet == 0
        || config.max_ack_ranges == 0
    {
        return invalid_config("packet, datagram, frame, and ACK-range limits must be nonzero");
    }
    Ok(())
}

fn invalid_config<T>(reason: &'static str) -> Result<T, QuicInspectError> {
    Err(QuicInspectError::InvalidConfig { reason })
}

fn malformed<T>(reason: &'static str) -> Result<T, QuicInspectError> {
    Err(QuicInspectError::Malformed { reason })
}

fn resource_limit<T>(resource: &'static str, limit: usize) -> Result<T, QuicInspectError> {
    Err(QuicInspectError::ResourceLimit { resource, limit })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LongPacketKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

struct ParsedLongPacket {
    start: usize,
    end: usize,
    pn_offset: usize,
    version: QuicVersion,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token: Vec<u8>,
    kind: LongPacketKind,
}

fn parse_long_packet(datagram: &[u8], start: usize) -> Result<ParsedLongPacket, QuicInspectError> {
    let mut cursor = WireCursor::at(datagram, start);
    let first = cursor.u8("missing long-header first byte")?;
    let version_wire = cursor.u32("truncated QUIC version")?;
    let version = QuicVersion::from_wire(version_wire)?;
    let wire_type = (first >> 4) & 0x03;
    let kind = match (version, wire_type) {
        (QuicVersion::V1, 0) | (QuicVersion::V2, 1) => LongPacketKind::Initial,
        (QuicVersion::V1, 1) | (QuicVersion::V2, 2) => LongPacketKind::ZeroRtt,
        (QuicVersion::V1, 2) | (QuicVersion::V2, 3) => LongPacketKind::Handshake,
        (QuicVersion::V1, 3) | (QuicVersion::V2, 0) => LongPacketKind::Retry,
        _ => return malformed("invalid long-header packet type"),
    };

    let dcid_len = usize::from(cursor.u8("missing DCID length")?);
    if dcid_len > MAX_CONNECTION_ID_LEN {
        return malformed("DCID exceeds 20 bytes");
    }
    let dcid = cursor.take(dcid_len, "truncated DCID")?.to_vec();
    let scid_len = usize::from(cursor.u8("missing SCID length")?);
    if scid_len > MAX_CONNECTION_ID_LEN {
        return malformed("SCID exceeds 20 bytes");
    }
    let scid = cursor.take(scid_len, "truncated SCID")?.to_vec();

    if kind == LongPacketKind::Retry {
        if cursor.remaining() < RETRY_INTEGRITY_TAG_LEN {
            return malformed("Retry packet has no integrity tag");
        }
        let token_len = cursor.remaining() - RETRY_INTEGRITY_TAG_LEN;
        let token = cursor.take(token_len, "truncated Retry token")?.to_vec();
        return Ok(ParsedLongPacket {
            start,
            end: datagram.len(),
            pn_offset: cursor.position,
            version,
            dcid,
            scid,
            token,
            kind,
        });
    }

    let mut token = Vec::new();
    if kind == LongPacketKind::Initial {
        let token_len = usize_from_varint(cursor.varint("truncated token length")?)?;
        token = cursor.take(token_len, "truncated Initial token")?.to_vec();
    }
    let packet_len = usize_from_varint(cursor.varint("truncated long-header length")?)?;
    if packet_len == 0 {
        return malformed("long-header packet has an empty protected payload");
    }
    let pn_offset = cursor.position;
    let end = pn_offset
        .checked_add(packet_len)
        .ok_or(QuicInspectError::Malformed {
            reason: "long-header packet length overflow",
        })?;
    if end > datagram.len() {
        return malformed("long-header packet exceeds its UDP datagram");
    }

    Ok(ParsedLongPacket {
        start,
        end,
        pn_offset,
        version,
        dcid,
        scid,
        token,
        kind,
    })
}

fn authenticate_retry(
    version: QuicVersion,
    original_dcid: &[u8],
    retry_packet: &[u8],
) -> Result<(), QuicInspectError> {
    if original_dcid.len() > MAX_CONNECTION_ID_LEN {
        return malformed("original DCID exceeds 20 bytes");
    }
    let tag_offset = retry_packet
        .len()
        .checked_sub(RETRY_INTEGRITY_TAG_LEN)
        .ok_or(QuicInspectError::Malformed {
            reason: "Retry packet has no integrity tag",
        })?;
    let mut pseudo_packet = Vec::with_capacity(1 + original_dcid.len() + tag_offset);
    pseudo_packet.push(u8::try_from(original_dcid.len()).expect("QUIC CID length fits u8"));
    pseudo_packet.extend_from_slice(original_dcid);
    pseudo_packet.extend_from_slice(&retry_packet[..tag_offset]);

    let (key, nonce) = match version {
        QuicVersion::V1 => (&V1_RETRY_KEY, V1_RETRY_NONCE),
        QuicVersion::V2 => (&V2_RETRY_KEY, V2_RETRY_NONCE),
    };
    let key = UnboundKey::new(&AES_128_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| QuicInspectError::InvalidConfig {
            reason: "Retry AES-128-GCM key initialization failed",
        })?;
    let mut tag = retry_packet[tag_offset..].to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(pseudo_packet),
            &mut tag,
        )
        .map_err(|_| QuicInspectError::AuthenticationFailed)?;
    if !plaintext.is_empty() {
        return malformed("Retry integrity input unexpectedly contained plaintext");
    }
    Ok(())
}

fn usize_from_varint(value: u64) -> Result<usize, QuicInspectError> {
    usize::try_from(value).map_err(|_| QuicInspectError::Malformed {
        reason: "QUIC variable integer does not fit usize",
    })
}

struct InitialKeys {
    version: QuicVersion,
    dcid: Vec<u8>,
    header: Box<dyn HeaderProtectionKey>,
    packet: Box<dyn PacketKey>,
    largest_packet_number: Option<u64>,
    authenticated_packet_numbers: HashSet<u64>,
    retry_packet_number_floor: Option<u64>,
}

impl InitialKeys {
    fn new(version: QuicVersion, dcid: Vec<u8>) -> Result<Self, QuicInspectError> {
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(rustls::Tls13CipherSuite::quic_suite)
            .ok_or(QuicInspectError::InvalidConfig {
                reason: "rustls ring AES-128-GCM has no QUIC suite",
            })?;
        let keys = suite.keys(&dcid, Side::Server, version.rustls());
        Ok(Self {
            version,
            dcid,
            header: keys.remote.header,
            packet: keys.remote.packet,
            largest_packet_number: None,
            authenticated_packet_numbers: HashSet::new(),
            retry_packet_number_floor: None,
        })
    }

    fn after_retry(self, dcid: Vec<u8>) -> Result<Self, QuicInspectError> {
        let mut next = Self::new(self.version, dcid)?;
        next.largest_packet_number = self.largest_packet_number;
        next.retry_packet_number_floor = self.largest_packet_number;
        next.authenticated_packet_numbers = self.authenticated_packet_numbers;
        Ok(next)
    }

    fn decrypt(
        &mut self,
        protected: &[u8],
        pn_offset: usize,
    ) -> Result<Option<Vec<u8>>, QuicInspectError> {
        let sample_start = pn_offset
            .checked_add(4)
            .ok_or(QuicInspectError::Malformed {
                reason: "header-protection sample offset overflow",
            })?;
        let sample_end = sample_start.checked_add(self.header.sample_len()).ok_or(
            QuicInspectError::Malformed {
                reason: "header-protection sample length overflow",
            },
        )?;
        if sample_end > protected.len() || pn_offset + 4 > protected.len() {
            return malformed("Initial is too short for a header-protection sample");
        }

        let mut first = protected[0];
        let mut packet_number_bytes = [0_u8; 4];
        packet_number_bytes.copy_from_slice(&protected[pn_offset..pn_offset + 4]);
        self.header
            .decrypt_in_place(
                &protected[sample_start..sample_end],
                &mut first,
                &mut packet_number_bytes,
            )
            .map_err(|_| QuicInspectError::AuthenticationFailed)?;

        let pn_len = usize::from((first & 0x03) + 1);
        let payload_start = pn_offset
            .checked_add(pn_len)
            .ok_or(QuicInspectError::Malformed {
                reason: "packet-number length overflow",
            })?;
        if payload_start > protected.len()
            || protected.len() - payload_start < self.packet.tag_len()
        {
            return malformed("Initial protected payload is shorter than its AEAD tag");
        }

        let truncated = packet_number_bytes[..pn_len]
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        let packet_number = decode_packet_number(
            self.largest_packet_number,
            truncated,
            u32::try_from(pn_len * 8).expect("packet-number length is at most four"),
        )?;

        let mut header = protected[..payload_start].to_vec();
        header[0] = first;
        header[pn_offset..payload_start].copy_from_slice(&packet_number_bytes[..pn_len]);
        let mut payload = protected[payload_start..].to_vec();
        let plaintext_len = self
            .packet
            .decrypt_in_place(packet_number, &header, &mut payload)
            .map_err(|_| QuicInspectError::AuthenticationFailed)?
            .len();

        // These bits are protected and are only meaningful after AEAD succeeds.
        if first & 0x0c != 0 {
            return malformed("authenticated Initial has nonzero reserved bits");
        }
        if self
            .retry_packet_number_floor
            .is_some_and(|floor| packet_number <= floor)
        {
            return malformed("client reset its Initial packet number after Retry");
        }
        if self.authenticated_packet_numbers.contains(&packet_number) {
            return Ok(None);
        }
        self.authenticated_packet_numbers.insert(packet_number);
        self.largest_packet_number = Some(
            self.largest_packet_number
                .map_or(packet_number, |largest| largest.max(packet_number)),
        );
        payload.truncate(plaintext_len);
        Ok(Some(payload))
    }
}

fn decode_packet_number(
    largest: Option<u64>,
    truncated: u64,
    bits: u32,
) -> Result<u64, QuicInspectError> {
    let expected = largest.map_or(0, |value| value.saturating_add(1));
    let window = 1_u64 << bits;
    let half_window = window / 2;
    let mask = window - 1;
    let mut candidate = (expected & !mask) | truncated;

    if candidate.saturating_add(half_window) <= expected
        && candidate <= MAX_PACKET_NUMBER.saturating_sub(window)
    {
        candidate += window;
    } else if candidate > expected.saturating_add(half_window) && candidate >= window {
        candidate -= window;
    }
    if candidate > MAX_PACKET_NUMBER {
        return malformed("decoded packet number exceeds QUIC's 62-bit limit");
    }
    Ok(candidate)
}

fn parse_initial_frames(
    plaintext: &[u8],
    crypto: &mut CryptoReassembly,
    config: QuicInspectConfig,
) -> Result<(), QuicInspectError> {
    let mut cursor = WireCursor::new(plaintext);
    let mut frames = 0usize;
    while cursor.remaining() != 0 {
        frames = frames
            .checked_add(1)
            .ok_or(QuicInspectError::ResourceLimit {
                resource: "frames per Initial packet",
                limit: config.max_frames_per_packet,
            })?;
        if frames > config.max_frames_per_packet {
            return resource_limit("frames per Initial packet", config.max_frames_per_packet);
        }

        if plaintext[cursor.position] == 0 {
            while cursor.remaining() != 0 && plaintext[cursor.position] == 0 {
                cursor.position += 1;
            }
            continue;
        }

        let frame_type = cursor.varint("truncated frame type")?;
        match frame_type {
            0x01 => {}
            0x02 | 0x03 => parse_ack_frame(&mut cursor, frame_type, config.max_ack_ranges)?,
            0x06 => {
                let offset = cursor.varint("truncated CRYPTO offset")?;
                let length = usize_from_varint(cursor.varint("truncated CRYPTO length")?)?;
                let bytes = cursor.take(length, "truncated CRYPTO data")?;
                crypto.insert(offset, bytes, config.max_crypto_bytes)?;
            }
            0x1c => {
                cursor.varint("truncated CONNECTION_CLOSE error code")?;
                cursor.varint("truncated CONNECTION_CLOSE frame type")?;
                let reason_len =
                    usize_from_varint(cursor.varint("truncated CONNECTION_CLOSE reason length")?)?;
                cursor.take(reason_len, "truncated CONNECTION_CLOSE reason")?;
            }
            _ => return Err(QuicInspectError::ForbiddenFrame { frame_type }),
        }
    }
    Ok(())
}

fn parse_ack_frame(
    cursor: &mut WireCursor<'_>,
    frame_type: u64,
    max_ranges: usize,
) -> Result<(), QuicInspectError> {
    let largest = cursor.varint("truncated ACK largest acknowledged")?;
    cursor.varint("truncated ACK delay")?;
    let range_count = cursor.varint("truncated ACK range count")?;
    if range_count > u64::try_from(max_ranges).unwrap_or(u64::MAX) {
        return resource_limit("ACK ranges", max_ranges);
    }
    let first_range = cursor.varint("truncated ACK first range")?;
    let mut smallest = largest
        .checked_sub(first_range)
        .ok_or(QuicInspectError::Malformed {
            reason: "ACK first range exceeds largest acknowledged",
        })?;
    for _ in 0..range_count {
        let gap = cursor.varint("truncated ACK gap")?;
        let range = cursor.varint("truncated ACK range")?;
        let next_largest = smallest
            .checked_sub(gap)
            .and_then(|value| value.checked_sub(2))
            .ok_or(QuicInspectError::Malformed {
                reason: "ACK gap underflows packet number space",
            })?;
        smallest = next_largest
            .checked_sub(range)
            .ok_or(QuicInspectError::Malformed {
                reason: "ACK range underflows packet number space",
            })?;
    }
    if frame_type == 0x03 {
        cursor.varint("truncated ACK_ECN ECT(0) count")?;
        cursor.varint("truncated ACK_ECN ECT(1) count")?;
        cursor.varint("truncated ACK_ECN CE count")?;
    }
    Ok(())
}

#[derive(Default)]
struct CryptoReassembly {
    bytes: Vec<u8>,
    present: Vec<bool>,
    contiguous: usize,
}

impl CryptoReassembly {
    fn insert(&mut self, offset: u64, data: &[u8], limit: usize) -> Result<(), QuicInspectError> {
        let start = usize::try_from(offset).map_err(|_| QuicInspectError::ResourceLimit {
            resource: "CRYPTO bytes",
            limit,
        })?;
        let end = start
            .checked_add(data.len())
            .ok_or(QuicInspectError::ResourceLimit {
                resource: "CRYPTO bytes",
                limit,
            })?;
        if end > limit {
            return resource_limit("CRYPTO bytes", limit);
        }
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
            self.present.resize(end, false);
        }
        for (index, byte) in (start..end).zip(data.iter().copied()) {
            if self.present[index] && self.bytes[index] != byte {
                return malformed("overlapping CRYPTO frames contain conflicting bytes");
            }
            self.bytes[index] = byte;
            self.present[index] = true;
        }
        while self.contiguous < self.present.len() && self.present[self.contiguous] {
            self.contiguous += 1;
        }
        Ok(())
    }

    fn client_hello(&self, limit: usize) -> Result<Option<String>, QuicInspectError> {
        if self.contiguous < HANDSHAKE_HEADER_LEN {
            return Ok(None);
        }
        if self.bytes[0] != CLIENT_HELLO_TYPE {
            return Err(TlsInspectError::Malformed {
                reason: "first QUIC CRYPTO handshake message is not ClientHello",
            }
            .into());
        }
        let body_len = (usize::from(self.bytes[1]) << 16)
            | (usize::from(self.bytes[2]) << 8)
            | usize::from(self.bytes[3]);
        let message_len =
            HANDSHAKE_HEADER_LEN
                .checked_add(body_len)
                .ok_or(QuicInspectError::ResourceLimit {
                    resource: "CRYPTO bytes",
                    limit,
                })?;
        if message_len > limit {
            return resource_limit("CRYPTO bytes", limit);
        }
        if self.contiguous < message_len {
            return Ok(None);
        }
        Ok(Some(parse_client_hello(
            &self.bytes[HANDSHAKE_HEADER_LEN..message_len],
        )?))
    }
}

struct WireCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn at(bytes: &'a [u8], position: usize) -> Self {
        Self { bytes, position }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize, reason: &'static str) -> Result<&'a [u8], QuicInspectError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(QuicInspectError::Malformed { reason })?;
        if end > self.bytes.len() {
            return malformed(reason);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self, reason: &'static str) -> Result<u8, QuicInspectError> {
        Ok(self.take(1, reason)?[0])
    }

    fn u32(&mut self, reason: &'static str) -> Result<u32, QuicInspectError> {
        let bytes = self.take(4, reason)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn varint(&mut self, reason: &'static str) -> Result<u64, QuicInspectError> {
        let first = self.u8(reason)?;
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(len - 1, reason)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use rustls::quic::DirectionalKeys;

    use super::*;

    #[test]
    fn decrypts_rfc_9001_v1_client_initial() {
        let datagram = decode_hex(RFC_9001_V1_CLIENT_INITIAL);
        assert_eq!(datagram.len(), 1200);

        let mut inspector = inspector();
        let inspected = inspector
            .inspect_datagram(&datagram)
            .expect("RFC 9001 packet authenticates")
            .expect("RFC 9001 packet contains a complete ClientHello");

        assert_eq!(inspected.server_name, "example.com");
        assert_eq!(inspected.version, QuicVersion::V1);
        assert_eq!(
            inspected.destination_connection_id,
            decode_hex("8394c8f03e515708")
        );
    }

    #[test]
    fn classifies_supported_initial_before_authentication() {
        for (vector, version) in [
            (RFC_9001_V1_CLIENT_INITIAL, QuicVersion::V1),
            (RFC_9369_V2_CLIENT_INITIAL, QuicVersion::V2),
        ] {
            let header = parse_client_initial_header(&decode_hex(vector))
                .expect("RFC client Initial header is structurally valid");
            assert_eq!(header.version, version);
            assert_eq!(
                header.destination_connection_id,
                decode_hex("8394c8f03e515708")
            );
        }
    }

    #[test]
    fn decrypts_rfc_9369_v2_client_initial() {
        let datagram = decode_hex(RFC_9369_V2_CLIENT_INITIAL);
        assert_eq!(datagram.len(), 1200);

        let mut inspector = inspector();
        let inspected = inspector
            .inspect_datagram(&datagram)
            .expect("RFC 9369 packet authenticates")
            .expect("RFC 9369 packet contains a complete ClientHello");

        assert_eq!(inspected.server_name, "example.com");
        assert_eq!(inspected.version, QuicVersion::V2);
        assert_eq!(
            inspected.destination_connection_id,
            decode_hex("8394c8f03e515708")
        );
    }

    #[test]
    fn accepts_rfc_9001_v1_retry_transition() {
        assert_rfc_retry_transition(QuicVersion::V1, RFC_9001_V1_RETRY);
    }

    #[test]
    fn accepts_rfc_9369_v2_retry_transition() {
        assert_rfc_retry_transition(QuicVersion::V2, RFC_9369_V2_RETRY);
    }

    #[test]
    fn completed_inspection_restarts_crypto_reassembly_after_retry() {
        let original_dcid = decode_hex("8394c8f03e515708");
        let retry_scid = decode_hex("f067a5502a4262b5");
        let initial_hello = client_hello(b"before-retry.example", &[]);
        let initial = encrypted_initial_with_fields(
            QuicVersion::V1,
            &original_dcid,
            &[],
            &[],
            0,
            &crypto_frame(0, &initial_hello),
        );
        let mut inspector = inspector();
        let before = inspector
            .inspect_datagram(&initial)
            .expect("initial ClientHello authenticates")
            .expect("initial ClientHello is complete");
        assert_eq!(before.server_name, "before-retry.example");

        let accepted = inspector
            .accept_retry_if_present(&decode_hex(RFC_9001_V1_RETRY))
            .expect("RFC Retry authenticates")
            .expect("datagram is classified as Retry");
        let QuicRetryAcceptance::New(accepted) = accepted else {
            panic!("first authenticated Retry must create the transition");
        };
        assert_eq!(accepted.retry_source_connection_id, retry_scid);

        let post_retry_hello = client_hello(b"after-retry.example", &[]);
        let post_retry = encrypted_initial_with_fields(
            QuicVersion::V1,
            &accepted.retry_source_connection_id,
            &[],
            &accepted.token,
            1,
            &crypto_frame(0, &post_retry_hello),
        );
        let after = inspector
            .inspect_datagram(&post_retry)
            .expect("post-Retry ClientHello authenticates")
            .expect("post-Retry ClientHello is reassembled independently");
        assert_eq!(after.server_name, "after-retry.example");
    }

    #[test]
    fn exact_retry_retransmission_is_idempotent_but_changed_retry_fails_closed() {
        let original_dcid = decode_hex("8394c8f03e515708");
        let retry = decode_hex(RFC_9001_V1_RETRY);
        let mut inspector = inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 0);
        assert!(matches!(
            inspector
                .accept_retry_if_present(&retry)
                .expect("first Retry authenticates"),
            Some(QuicRetryAcceptance::New(_))
        ));
        assert!(matches!(
            inspector
                .accept_retry_if_present(&retry)
                .expect("exact Retry retransmission authenticates"),
            Some(QuicRetryAcceptance::Duplicate(_))
        ));

        let mut changed = retry;
        changed[18] ^= 1;
        let error = inspector
            .accept_retry_if_present(&changed)
            .expect_err("changed Retry must fail closed");
        assert!(matches!(
            error,
            QuicInspectError::AuthenticationFailed | QuicInspectError::Malformed { .. }
        ));
    }

    #[test]
    fn rejects_retry_tamper_and_mismatched_original_dcid() {
        let original_dcid = decode_hex("8394c8f03e515708");
        let mut tampered = decode_hex(RFC_9001_V1_RETRY);
        *tampered.last_mut().expect("Retry vector is nonempty") ^= 1;
        let mut inspector = inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 0);
        let error = inspector
            .accept_retry(&tampered)
            .expect_err("modified Retry tag must not authenticate");
        assert!(matches!(error, QuicInspectError::AuthenticationFailed));

        let wrong_original_dcid = decode_hex("8394c8f03e515709");
        let mut inspector = inspector_after_initial(QuicVersion::V1, &wrong_original_dcid, &[], 0);
        let error = inspector
            .accept_retry(&decode_hex(RFC_9001_V1_RETRY))
            .expect_err("Retry tag is bound to the original DCID");
        assert!(matches!(error, QuicInspectError::AuthenticationFailed));
    }

    #[test]
    fn requires_retry_token_dcid_scid_and_monotonic_packet_number() {
        let original_dcid = decode_hex("8394c8f03e515708");
        let retry_scid = decode_hex("f067a5502a4262b5");
        let retry = decode_hex(RFC_9001_V1_RETRY);
        let handshake = client_hello(b"retry.example", &[]);

        let mut wrong_token = inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 7);
        wrong_token.accept_retry(&retry).expect("valid Retry");
        let packet = encrypted_initial_with_fields(
            QuicVersion::V1,
            &retry_scid,
            &[],
            b"tokem",
            8,
            &crypto_frame(0, &handshake),
        );
        let error = wrong_token
            .inspect_datagram(&packet)
            .expect_err("post-Retry Initial must repeat the exact token");
        assert!(matches!(error, QuicInspectError::Malformed { .. }));

        let mut mismatched_destination =
            inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 7);
        mismatched_destination
            .accept_retry(&retry)
            .expect("valid Retry");
        let packet = encrypted_initial_with_fields(
            QuicVersion::V1,
            &decode_hex("f067a5502a4262b4"),
            &[],
            b"token",
            8,
            &crypto_frame(0, &handshake),
        );
        let error = mismatched_destination
            .inspect_datagram(&packet)
            .expect_err("post-Retry DCID must be the Retry SCID");
        assert!(matches!(error, QuicInspectError::Malformed { .. }));

        let mut changed_client_source =
            inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 7);
        changed_client_source
            .accept_retry(&retry)
            .expect("valid Retry");
        let packet = encrypted_initial_with_fields(
            QuicVersion::V1,
            &retry_scid,
            b"changed",
            b"token",
            8,
            &crypto_frame(0, &handshake),
        );
        let error = changed_client_source
            .inspect_datagram(&packet)
            .expect_err("client SCID must survive Retry unchanged");
        assert!(matches!(error, QuicInspectError::Malformed { .. }));

        let mut reset_packet_number =
            inspector_after_initial(QuicVersion::V1, &original_dcid, &[], 7);
        reset_packet_number
            .accept_retry(&retry)
            .expect("valid Retry");
        let packet = encrypted_initial_with_fields(
            QuicVersion::V1,
            &retry_scid,
            &[],
            b"token",
            0,
            &crypto_frame(0, &handshake),
        );
        let error = reset_packet_number
            .inspect_datagram(&packet)
            .expect_err("Retry does not reset the Initial packet number space");
        assert!(matches!(error, QuicInspectError::Malformed { .. }));
    }

    #[test]
    fn reassembles_fragmented_reordered_and_duplicate_crypto() {
        let handshake = client_hello(b"Reordered.Example", &[]);
        let first_split = 23;
        let second_split = 61;
        let dcid = decode_hex("8394c8f03e515708");
        let packets = [
            encrypted_initial(
                QuicVersion::V1,
                &dcid,
                10,
                &crypto_frame(first_split, &handshake[first_split..second_split]),
            ),
            encrypted_initial(
                QuicVersion::V1,
                &dcid,
                9,
                &crypto_frame(0, &handshake[..first_split]),
            ),
            encrypted_initial(
                QuicVersion::V1,
                &dcid,
                10,
                &crypto_frame(first_split, &handshake[first_split..second_split]),
            ),
            encrypted_initial(
                QuicVersion::V1,
                &dcid,
                11,
                &crypto_frame(second_split, &handshake[second_split..]),
            ),
        ];

        let mut inspector = inspector();
        for packet in &packets[..3] {
            assert_eq!(
                inspector.inspect_datagram(packet).expect("valid fragment"),
                None
            );
        }
        let inspected = inspector
            .inspect_datagram(&packets[3])
            .expect("last fragment authenticates")
            .expect("last fragment completes ClientHello");
        assert_eq!(inspected.server_name, "reordered.example");
    }

    #[test]
    fn rejects_conflicting_crypto_overlap() {
        let dcid = decode_hex("8394c8f03e515708");
        let first = encrypted_initial(QuicVersion::V1, &dcid, 0, &crypto_frame(10, b"abcdef"));
        let conflicting = encrypted_initial(QuicVersion::V1, &dcid, 1, &crypto_frame(12, b"ZZ"));
        let mut inspector = inspector();
        assert_eq!(
            inspector.inspect_datagram(&first).expect("first fragment"),
            None
        );

        let error = inspector
            .inspect_datagram(&conflicting)
            .expect_err("conflicting overlap must fail closed");
        assert!(matches!(error, QuicInspectError::Malformed { .. }));
    }

    #[test]
    fn rejects_ech_even_with_outer_sni() {
        let handshake = client_hello(b"public.example", &[(0xfe0d, &[0])]);
        let packet = encrypted_initial(
            QuicVersion::V2,
            &decode_hex("8394c8f03e515708"),
            0,
            &crypto_frame(0, &handshake),
        );
        let mut inspector = inspector();

        let error = inspector
            .inspect_datagram(&packet)
            .expect_err("ECH outer SNI is not a route");
        assert!(matches!(
            error,
            QuicInspectError::Tls(TlsInspectError::EncryptedClientHello)
        ));
    }

    #[test]
    fn rejects_tampering_and_unsupported_versions() {
        let dcid = decode_hex("8394c8f03e515708");
        let handshake = client_hello(b"auth.example", &[]);
        let mut tampered =
            encrypted_initial(QuicVersion::V1, &dcid, 0, &crypto_frame(0, &handshake));
        *tampered.last_mut().expect("nonempty packet") ^= 1;
        let error = inspector()
            .inspect_datagram(&tampered)
            .expect_err("modified ciphertext must not authenticate");
        assert!(matches!(error, QuicInspectError::AuthenticationFailed));

        let mut unsupported =
            encrypted_initial(QuicVersion::V1, &dcid, 0, &crypto_frame(0, &handshake));
        unsupported[1..5].copy_from_slice(&0x709a_50c4_u32.to_be_bytes());
        let error = inspector()
            .inspect_datagram(&unsupported)
            .expect_err("provisional v2 codepoint is unsupported");
        assert!(matches!(
            error,
            QuicInspectError::UnsupportedVersion(0x709a_50c4)
        ));
    }

    #[test]
    fn enforces_crypto_and_packet_count_limits() {
        let dcid = decode_hex("8394c8f03e515708");
        let packet = encrypted_initial(QuicVersion::V1, &dcid, 0, &crypto_frame(64, b"x"));
        let config = QuicInspectConfig {
            max_crypto_bytes: 64,
            ..QuicInspectConfig::default()
        };
        let error = QuicInitialInspector::new(config)
            .expect("valid tight config")
            .inspect_datagram(&packet)
            .expect_err("CRYPTO offset over limit must fail");
        assert!(matches!(error, QuicInspectError::ResourceLimit { .. }));

        let incomplete = encrypted_initial(QuicVersion::V1, &dcid, 1, &crypto_frame(5, b"x"));
        let config = QuicInspectConfig {
            max_initial_packets: 1,
            ..QuicInspectConfig::default()
        };
        let mut bounded = QuicInitialInspector::new(config).expect("valid packet limit");
        assert_eq!(
            bounded.inspect_datagram(&incomplete).expect("first packet"),
            None
        );
        let error = bounded
            .inspect_datagram(&incomplete)
            .expect_err("second packet exceeds attempt limit even if duplicate");
        assert!(matches!(error, QuicInspectError::ResourceLimit { .. }));
    }

    fn inspector() -> QuicInitialInspector {
        QuicInitialInspector::new(QuicInspectConfig::default()).expect("valid defaults")
    }

    fn assert_rfc_retry_transition(version: QuicVersion, retry_vector: &str) {
        let original_dcid = decode_hex("8394c8f03e515708");
        let retry_scid = decode_hex("f067a5502a4262b5");
        let mut inspector = inspector_after_initial(version, &original_dcid, &[], 0);
        let accepted = inspector
            .accept_retry(&decode_hex(retry_vector))
            .expect("RFC Retry integrity tag authenticates");
        assert_eq!(accepted.version, version);
        assert_eq!(accepted.original_destination_connection_id, original_dcid);
        assert_eq!(accepted.retry_source_connection_id, retry_scid);
        assert_eq!(accepted.token, b"token");

        let handshake = client_hello(b"retry.example", &[]);
        let post_retry = encrypted_initial_with_fields(
            version,
            &accepted.retry_source_connection_id,
            &[],
            &accepted.token,
            1,
            &crypto_frame(0, &handshake),
        );
        let inspected = inspector
            .inspect_datagram(&post_retry)
            .expect("post-Retry Initial authenticates")
            .expect("post-Retry ClientHello is complete");
        assert_eq!(inspected.server_name, "retry.example");
        assert_eq!(inspected.version, version);
        assert_eq!(
            inspected.destination_connection_id,
            accepted.retry_source_connection_id
        );
    }

    fn inspector_after_initial(
        version: QuicVersion,
        original_dcid: &[u8],
        client_scid: &[u8],
        packet_number: u64,
    ) -> QuicInitialInspector {
        let first_initial = encrypted_initial_with_fields(
            version,
            original_dcid,
            client_scid,
            &[],
            packet_number,
            &[0x01],
        );
        let mut inspector = inspector();
        assert_eq!(
            inspector
                .inspect_datagram(&first_initial)
                .expect("first Initial authenticates"),
            None
        );
        inspector
    }

    fn encrypted_initial(
        version: QuicVersion,
        dcid: &[u8],
        packet_number: u64,
        frames: &[u8],
    ) -> Vec<u8> {
        encrypted_initial_with_fields(version, dcid, &[], &[], packet_number, frames)
    }

    fn encrypted_initial_with_fields(
        version: QuicVersion,
        dcid: &[u8],
        scid: &[u8],
        token: &[u8],
        packet_number: u64,
        frames: &[u8],
    ) -> Vec<u8> {
        const PN_LEN: usize = 2;
        let mut plaintext = frames.to_vec();
        let (mut header, pn_offset) = loop {
            let candidate = initial_header(version, dcid, scid, token, PN_LEN, plaintext.len());
            let total = candidate.0.len() + PN_LEN + plaintext.len() + 16;
            if total == MIN_INITIAL_DATAGRAM_LEN {
                break candidate;
            }
            if total < MIN_INITIAL_DATAGRAM_LEN {
                plaintext.resize(plaintext.len() + MIN_INITIAL_DATAGRAM_LEN - total, 0);
            } else {
                let shortened = plaintext.len() - (total - MIN_INITIAL_DATAGRAM_LEN);
                assert!(
                    shortened >= frames.len(),
                    "only synthetic padding is removed"
                );
                plaintext.truncate(shortened);
            }
        };
        let pn = u16::try_from(packet_number)
            .expect("test packet number fits two bytes")
            .to_be_bytes();
        header.extend_from_slice(&pn);

        let DirectionalKeys {
            header: header_key,
            packet: packet_key,
        } = client_initial_keys(version, dcid);
        let mut payload = plaintext;
        let tag = packet_key
            .encrypt_in_place(packet_number, &header, &mut payload)
            .expect("test encryption succeeds");
        let mut protected = header;
        protected.extend_from_slice(&payload);
        protected.extend_from_slice(tag.as_ref());

        let sample_start = pn_offset + 4;
        let sample = protected[sample_start..sample_start + header_key.sample_len()].to_vec();
        let mut first = protected[0];
        let mut protected_pn = protected[pn_offset..pn_offset + PN_LEN].to_vec();
        header_key
            .encrypt_in_place(&sample, &mut first, &mut protected_pn)
            .expect("test header protection succeeds");
        protected[0] = first;
        protected[pn_offset..pn_offset + PN_LEN].copy_from_slice(&protected_pn);
        assert_eq!(protected.len(), MIN_INITIAL_DATAGRAM_LEN);
        protected
    }

    fn client_initial_keys(version: QuicVersion, dcid: &[u8]) -> DirectionalKeys {
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(rustls::Tls13CipherSuite::quic_suite)
            .expect("ring suite supports QUIC");
        suite.keys(dcid, Side::Client, version.rustls()).local
    }

    fn initial_header(
        version: QuicVersion,
        dcid: &[u8],
        scid: &[u8],
        token: &[u8],
        pn_len: usize,
        plaintext_len: usize,
    ) -> (Vec<u8>, usize) {
        let type_bits = match version {
            QuicVersion::V1 => 0,
            QuicVersion::V2 => 1,
        };
        let mut header =
            vec![0xc0 | (type_bits << 4) | u8::try_from(pn_len - 1).expect("PN length fits")];
        let version_wire = match version {
            QuicVersion::V1 => QUIC_V1,
            QuicVersion::V2 => QUIC_V2,
        };
        header.extend_from_slice(&version_wire.to_be_bytes());
        header.push(u8::try_from(dcid.len()).expect("test DCID length fits"));
        header.extend_from_slice(dcid);
        header.push(u8::try_from(scid.len()).expect("test SCID length fits"));
        header.extend_from_slice(scid);
        encode_varint(
            u64::try_from(token.len()).expect("test token length fits"),
            &mut header,
        );
        header.extend_from_slice(token);
        encode_varint(
            u64::try_from(pn_len + plaintext_len + 16).expect("test packet length fits"),
            &mut header,
        );
        let pn_offset = header.len();
        (header, pn_offset)
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        encode_varint(u64::try_from(offset).expect("test offset fits"), &mut frame);
        encode_varint(
            u64::try_from(data.len()).expect("test length fits"),
            &mut frame,
        );
        frame.extend_from_slice(data);
        frame
    }

    fn encode_varint(value: u64, target: &mut Vec<u8>) {
        match value {
            0..=63 => target.push(u8::try_from(value).expect("one-byte varint")),
            64..=16_383 => {
                let encoded = u16::try_from(value).expect("two-byte varint") | 0x4000;
                target.extend_from_slice(&encoded.to_be_bytes());
            }
            16_384..=1_073_741_823 => {
                let encoded = u32::try_from(value).expect("four-byte varint") | 0x8000_0000;
                target.extend_from_slice(&encoded.to_be_bytes());
            }
            _ if value <= MAX_PACKET_NUMBER => {
                target.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
            }
            _ => panic!("test varint exceeds 62 bits"),
        }
    }

    fn client_hello(sni: &[u8], extra_extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut server_name = Vec::new();
        push_u16(&mut server_name, 3 + sni.len());
        server_name.push(0);
        push_u16(&mut server_name, sni.len());
        server_name.extend_from_slice(sni);

        let mut extensions = Vec::new();
        push_u16(&mut extensions, 0);
        push_u16(&mut extensions, server_name.len());
        extensions.extend_from_slice(&server_name);
        for (extension_type, payload) in extra_extensions {
            push_u16(&mut extensions, usize::from(*extension_type));
            push_u16(&mut extensions, payload.len());
            extensions.extend_from_slice(payload);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        push_u16(&mut body, extensions.len());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![CLIENT_HELLO_TYPE];
        let encoded_len = u32::try_from(body.len())
            .expect("test ClientHello length fits")
            .to_be_bytes();
        handshake.extend_from_slice(&encoded_len[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn push_u16(target: &mut Vec<u8>, value: usize) {
        target.extend_from_slice(
            &u16::try_from(value)
                .expect("test value fits u16")
                .to_be_bytes(),
        );
    }

    fn decode_hex(encoded: &str) -> Vec<u8> {
        let digits: Vec<_> = encoded.bytes().filter(u8::is_ascii_hexdigit).collect();
        assert_eq!(digits.len() % 2, 0, "hex digit count must be even");
        digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }

    const RFC_9001_V1_RETRY: &str =
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

    const RFC_9369_V2_RETRY: &str =
        "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6";

    const RFC_9001_V1_CLIENT_INITIAL: &str = r"
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
";

    const RFC_9369_V2_CLIENT_INITIAL: &str = r"
d76b3343cf088394c8f03e5157080000 449ea0c95e82ffe67b6abcdb4298b485
dd04de806071bf03dceebfa162e75d6c 96058bdbfb127cdfcbf903388e99ad04
9f9a3dd4425ae4d0992cfff18ecf0fdb 5a842d09747052f17ac2053d21f57c5d
250f2c4f0e0202b70785b7946e992e58 a59ac52dea6774d4f03b55545243cf1a
12834e3f249a78d395e0d18f4d766004 f1a2674802a747eaa901c3f10cda5500
cb9122faa9f1df66c392079a1b40f0de 1c6054196a11cbea40afb6ef5253cd68
18f6625efce3b6def6ba7e4b37a40f77 32e093daa7d52190935b8da58976ff33
12ae50b187c1433c0f028edcc4c2838b 6a9bfc226ca4b4530e7a4ccee1bfa2a3
d396ae5a3fb512384b2fdd851f784a65 e03f2c4fbe11a53c7777c023462239dd
6f7521a3f6c7d5dd3ec9b3f233773d4b 46d23cc375eb198c63301c21801f6520
bcfb7966fc49b393f0061d974a2706df 8c4a9449f11d7f3d2dcbb90c6b877045
636e7c0c0fe4eb0f697545460c806910 d2c355f1d253bc9d2452aaa549e27a1f
ac7cf4ed77f322e8fa894b6a83810a34 b361901751a6f5eb65a0326e07de7c12
16ccce2d0193f958bb3850a833f7ae43 2b65bc5a53975c155aa4bcb4f7b2c4e5
4df16efaf6ddea94e2c50b4cd1dfe060 17e0e9d02900cffe1935e0491d77ffb4
fdf85290fdd893d577b1131a610ef6a5 c32b2ee0293617a37cbb08b847741c3b
8017c25ca9052ca1079d8b78aebd4787 6d330a30f6a8c6d61dd1ab5589329de7
14d19d61370f8149748c72f132f0fc99 f34d766c6938597040d8f9e2bb522ff9
9c63a344d6a2ae8aa8e51b7b90a4a806 105fcbca31506c446151adfeceb51b91
abfe43960977c87471cf9ad4074d30e1 0d6a7f03c63bd5d4317f68ff325ba3bd
80bf4dc8b52a0ba031758022eb025cdd 770b44d6d6cf0670f4e990b22347a7db
848265e3e5eb72dfe8299ad7481a4083 22cac55786e52f633b2fb6b614eaed18
d703dd84045a274ae8bfa73379661388 d6991fe39b0d93debb41700b41f90a15
c4d526250235ddcd6776fc77bc97e7a4 17ebcb31600d01e57f32162a8560cacc
7e27a096d37a1a86952ec71bd89a3e9a 30a2a26162984d7740f81193e8238e61
f6b5b984d4d3dfa033c1bb7e4f0037fe bf406d91c0dccf32acf423cfa1e70710
10d3f270121b493ce85054ef58bada42 310138fe081adb04e2bd901f2f13458b
3d6758158197107c14ebb193230cd115 7380aa79cae1374a7c1e5bbcb80ee23e
06ebfde206bfb0fcbc0edc4ebec30966 1bdd908d532eb0c6adc38b7ca7331dce
8dfce39ab71e7c32d318d136b6100671 a1ae6a6600e3899f31f0eed19e3417d1
34b90c9058f8632c798d4490da498730 7cba922d61c39805d072b589bd52fdf1
e86215c2d54e6670e07383a27bbffb5a ddf47d66aa85a0c6f9f32e59d85a44dd
5d3b22dc2be80919b490437ae4f36a0a e55edf1d0b5cb4e9a3ecabee93dfc6e3
8d209d0fa6536d27a5d6fbb17641cde2 7525d61093f1b28072d111b2b4ae5f89
d5974ee12e5cf7d5da4d6a31123041f3 3e61407e76cffcdcfd7e19ba58cf4b53
6f4c4938ae79324dc402894b44faf8af bab35282ab659d13c93f70412e85cb19
9a37ddec600545473cfb5a05e08d0b20 9973b2172b4d21fb69745a262ccde96b
a18b2faa745b6fe189cf772a9f84cbfc
";
}
