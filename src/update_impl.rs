//! Authenticated, repository-pinned self-update support.
//!
//! The default build deliberately has no trust root. It rejects `update`
//! before constructing a network client or touching the filesystem. Release
//! builds may pin one `owner/repository` and one Ed25519 public key through the
//! compile-time environment variables documented in `packaging/README.md`.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

use reqwest::{Client, redirect::Policy};
use ring::{digest, signature};
use semver::Version;
use serde::Deserialize;
use thiserror::Error;

pub const PINNED_REPOSITORY: Option<&str> = option_env!("RS_PROXY_UPDATE_REPOSITORY");
pub const PINNED_PUBLIC_KEY: Option<&str> = option_env!("RS_PROXY_UPDATE_PUBLIC_KEY");

const MANIFEST_ASSET_NAME: &str = "rs-proxy-manifest.toml";
const SIGNATURE_ASSET_NAME: &str = "rs-proxy-manifest.toml.sig";
const RELEASES_PER_PAGE: usize = 100;
const MAX_RELEASE_PAGES: usize = 10;
const MAX_RELEASE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024;
const MAX_BINARY_BYTES: usize = 256 * 1024 * 1024;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SHA256_BYTES: usize = 32;
const MANIFEST_SCHEMA: u32 = 1;
const USER_AGENT: &str = concat!("rs-proxy/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateMode {
    CheckOnly,
    Install,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStatus {
    UpToDate,
    Available,
    Installed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOutcome {
    pub current: Version,
    pub latest: Version,
    pub status: UpdateStatus,
    pub installed_path: Option<PathBuf>,
    pub retained_rollback_path: Option<PathBuf>,
    pub cleanup_warning: Option<String>,
}

impl fmt::Display for UpdateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            UpdateStatus::UpToDate => write!(
                formatter,
                "rs-proxy {} is up to date (authenticated latest: {})",
                self.current, self.latest
            ),
            UpdateStatus::Available => write!(
                formatter,
                "authenticated update available: {} -> {}",
                self.current, self.latest
            ),
            UpdateStatus::Installed => {
                let path = self
                    .installed_path
                    .as_deref()
                    .expect("installed outcome always has a path");
                write!(
                    formatter,
                    "installed authenticated update {} -> {} at {}; restart explicitly to use it",
                    self.current,
                    self.latest,
                    path.display()
                )?;
                if let Some(rollback) = &self.retained_rollback_path {
                    write!(
                        formatter,
                        "; retained recovery link at {}",
                        rollback.display()
                    )?;
                }
                if let Some(warning) = &self.cleanup_warning {
                    write!(formatter, "; cleanup warning: {warning}")?;
                }
                Ok(())
            }
        }
    }
}

/// Check for or install an authenticated release from the build-pinned repository.
///
/// # Errors
///
/// Returns a fail-closed error for missing/invalid build-time trust, network
/// failures, unauthenticated metadata, an invalid artifact, or replacement
/// failure. Missing trust is checked before network or filesystem I/O.
pub async fn run(mode: UpdateMode) -> Result<UpdateOutcome, UpdateError> {
    let trust = TrustConfig::from_build()?;
    let target = Target::current()?;
    let current = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|error| {
        UpdateError::InvalidCurrentVersion {
            reason: error.to_string(),
        }
    })?;
    let installer = CurrentExecutableInstaller::new(mode)?;
    let transport = HttpTransport::new()?;
    execute(&transport, &installer, &trust, target, &current, mode).await
}

#[derive(Clone, Debug)]
struct TrustConfig {
    repository: String,
    public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl TrustConfig {
    fn from_build() -> Result<Self, UpdateError> {
        Self::from_options(PINNED_REPOSITORY, PINNED_PUBLIC_KEY)
    }

    fn from_options(
        repository: Option<&str>,
        public_key: Option<&str>,
    ) -> Result<Self, UpdateError> {
        let (Some(repository), Some(public_key)) = (repository, public_key) else {
            return Err(UpdateError::TrustNotConfigured);
        };
        validate_repository(repository)?;
        let public_key = decode_fixed_hex::<ED25519_PUBLIC_KEY_BYTES>(public_key)
            .map_err(|reason| UpdateError::InvalidPinnedPublicKey { reason })?;
        Ok(Self {
            repository: repository.to_owned(),
            public_key,
        })
    }
}

fn validate_repository(repository: &str) -> Result<(), UpdateError> {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    let valid_component = |component: &str| {
        !component.is_empty()
            && component.len() <= 100
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && component != "."
            && component != ".."
    };
    if parts.next().is_some() || !valid_component(owner) || !valid_component(name) {
        return Err(UpdateError::InvalidPinnedRepository {
            repository: repository.to_owned(),
        });
    }
    Ok(())
}

trait Transport {
    async fn get(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, UpdateError>;
}

struct HttpTransport {
    client: Client,
}

impl HttpTransport {
    fn new() -> Result<Self, UpdateError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .redirect(Policy::custom(|attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("too many redirects");
                }
                if attempt.url().scheme() != "https" {
                    return attempt.error("refusing a non-HTTPS redirect");
                }
                attempt.follow()
            }))
            .build()
            .map_err(|error| UpdateError::HttpClient {
                reason: error.to_string(),
            })?;
        Ok(Self { client })
    }
}

impl Transport for HttpTransport {
    async fn get(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, UpdateError> {
        let parsed = reqwest::Url::parse(url).map_err(|error| UpdateError::Download {
            url: url.to_owned(),
            reason: format!("invalid URL: {error}"),
        })?;
        if parsed.scheme() != "https" {
            return Err(UpdateError::Download {
                url: url.to_owned(),
                reason: "only HTTPS is allowed".to_owned(),
            });
        }

        let mut response =
            self.client
                .get(parsed)
                .send()
                .await
                .map_err(|error| UpdateError::Download {
                    url: url.to_owned(),
                    reason: error.to_string(),
                })?;
        if response.url().scheme() != "https" {
            return Err(UpdateError::Download {
                url: url.to_owned(),
                reason: "final response URL is not HTTPS".to_owned(),
            });
        }
        if !response.status().is_success() {
            return Err(UpdateError::Download {
                url: url.to_owned(),
                reason: format!("HTTP status {}", response.status()),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum_bytes as u64)
        {
            return Err(UpdateError::DownloadTooLarge {
                url: url.to_owned(),
                maximum_bytes,
            });
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| UpdateError::Download {
                url: url.to_owned(),
                reason: error.to_string(),
            })?
        {
            let new_length = body.len().checked_add(chunk.len()).ok_or_else(|| {
                UpdateError::DownloadTooLarge {
                    url: url.to_owned(),
                    maximum_bytes,
                }
            })?;
            if new_length > maximum_bytes {
                return Err(UpdateError::DownloadTooLarge {
                    url: url.to_owned(),
                    maximum_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ApiRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ApiAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug)]
struct SelectedRelease {
    version: Version,
    release: ApiRelease,
}

async fn latest_stable_release<T: Transport>(
    transport: &T,
    repository: &str,
) -> Result<SelectedRelease, UpdateError> {
    let mut selected: Option<SelectedRelease> = None;
    for page in 1..=MAX_RELEASE_PAGES {
        let url = format!(
            "https://api.github.com/repos/{repository}/releases?per_page={RELEASES_PER_PAGE}&page={page}"
        );
        let body = transport.get(&url, MAX_RELEASE_RESPONSE_BYTES).await?;
        let releases: Vec<ApiRelease> =
            serde_json::from_slice(&body).map_err(|error| UpdateError::InvalidReleaseResponse {
                reason: error.to_string(),
            })?;
        let count = releases.len();
        for release in releases {
            let Some(version) = stable_tag_version(&release) else {
                continue;
            };
            if selected
                .as_ref()
                .is_none_or(|current| version > current.version)
            {
                selected = Some(SelectedRelease { version, release });
            }
        }
        if count < RELEASES_PER_PAGE {
            return selected.ok_or(UpdateError::NoStableRelease);
        }
    }
    Err(UpdateError::ReleasePageLimit {
        maximum_pages: MAX_RELEASE_PAGES,
    })
}

fn stable_tag_version(release: &ApiRelease) -> Option<Version> {
    if release.draft || release.prerelease {
        return None;
    }
    let tag = release
        .tag_name
        .strip_prefix('v')
        .or_else(|| release.tag_name.strip_prefix('V'))
        .unwrap_or(&release.tag_name);
    let version = Version::parse(tag).ok()?;
    version.pre.is_empty().then_some(version)
}

fn release_asset_url(
    release: &ApiRelease,
    repository: &str,
    name: &str,
) -> Result<String, UpdateError> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| UpdateError::MissingReleaseAsset {
            name: name.to_owned(),
        })?;
    if matches.next().is_some() {
        return Err(UpdateError::DuplicateReleaseAsset {
            name: name.to_owned(),
        });
    }
    validate_asset_url(&asset.browser_download_url, repository)?;
    Ok(asset.browser_download_url.clone())
}

fn validate_asset_url(url: &str, repository: &str) -> Result<(), UpdateError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| UpdateError::UntrustedAssetUrl {
        url: url.to_owned(),
    })?;
    let expected_path = format!("/{repository}/releases/download/");
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some_and(|port| port != 443)
        || !parsed.path().starts_with(&expected_path)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(UpdateError::UntrustedAssetUrl {
            url: url.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    schema: u32,
    repository: String,
    version: String,
    assets: Vec<ManifestAsset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAsset {
    target: String,
    name: String,
    sha256: String,
}

#[derive(Debug)]
struct AuthenticatedArtifact {
    version: Version,
    name: String,
    sha256: [u8; SHA256_BYTES],
}

fn authenticate_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust: &TrustConfig,
    selected_version: &Version,
    target: Target,
) -> Result<AuthenticatedArtifact, UpdateError> {
    let encoded_signature = std::str::from_utf8(signature_bytes)
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?
        .trim();
    let signature = decode_fixed_hex::<ED25519_SIGNATURE_BYTES>(encoded_signature)
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, trust.public_key)
        .verify(manifest_bytes, &signature)
        .map_err(|_| UpdateError::InvalidManifestSignature)?;

    let manifest_text =
        std::str::from_utf8(manifest_bytes).map_err(|error| UpdateError::InvalidManifest {
            reason: error.to_string(),
        })?;
    let manifest: SignedManifest =
        toml::from_str(manifest_text).map_err(|error| UpdateError::InvalidManifest {
            reason: error.to_string(),
        })?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(UpdateError::InvalidManifest {
            reason: format!("unsupported schema {}", manifest.schema),
        });
    }
    if manifest.repository != trust.repository {
        return Err(UpdateError::ManifestRepositoryMismatch {
            expected: trust.repository.clone(),
            actual: manifest.repository,
        });
    }
    let version =
        Version::parse(&manifest.version).map_err(|error| UpdateError::InvalidManifest {
            reason: format!("invalid version: {error}"),
        })?;
    if !version.pre.is_empty() || &version != selected_version {
        return Err(UpdateError::ManifestVersionMismatch {
            expected: selected_version.clone(),
            actual: manifest.version,
        });
    }

    let mut matching_assets = manifest
        .assets
        .into_iter()
        .filter(|asset| asset.target == target.triple());
    let asset = matching_assets
        .next()
        .ok_or_else(|| UpdateError::ManifestTargetMissing {
            target: target.triple().to_owned(),
        })?;
    if matching_assets.next().is_some() {
        return Err(UpdateError::InvalidManifest {
            reason: format!("duplicate target {}", target.triple()),
        });
    }
    validate_asset_name(&asset.name)?;
    let sha256 = decode_fixed_hex::<SHA256_BYTES>(&asset.sha256).map_err(|reason| {
        UpdateError::InvalidManifest {
            reason: format!("invalid SHA-256 digest: {reason}"),
        }
    })?;
    Ok(AuthenticatedArtifact {
        version,
        name: asset.name,
        sha256,
    })
}

fn validate_asset_name(name: &str) -> Result<(), UpdateError> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || matches!(
            name,
            "." | ".." | MANIFEST_ASSET_NAME | SIGNATURE_ASSET_NAME
        )
    {
        return Err(UpdateError::InvalidManifest {
            reason: format!("unsafe asset name {name:?}"),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    X86_64Linux,
    Aarch64Linux,
    X86_64LinuxMusl,
    Aarch64LinuxMusl,
}

impl Target {
    fn current() -> Result<Self, UpdateError> {
        let environment = if cfg!(target_env = "gnu") {
            "gnu"
        } else if cfg!(target_env = "musl") {
            "musl"
        } else {
            "unknown"
        };
        Self::from_platform(std::env::consts::OS, std::env::consts::ARCH, environment)
    }

    fn from_platform(
        os: &'static str,
        architecture: &'static str,
        environment: &'static str,
    ) -> Result<Self, UpdateError> {
        match (os, architecture, environment) {
            ("linux", "x86_64", "gnu") => Ok(Self::X86_64Linux),
            ("linux", "aarch64", "gnu") => Ok(Self::Aarch64Linux),
            ("linux", "x86_64", "musl") => Ok(Self::X86_64LinuxMusl),
            ("linux", "aarch64", "musl") => Ok(Self::Aarch64LinuxMusl),
            _ => Err(UpdateError::UnsupportedPlatform {
                os,
                architecture,
                environment,
            }),
        }
    }

    const fn triple(self) -> &'static str {
        match self {
            Self::X86_64Linux => "x86_64-unknown-linux-gnu",
            Self::Aarch64Linux => "aarch64-unknown-linux-gnu",
            Self::X86_64LinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64LinuxMusl => "aarch64-unknown-linux-musl",
        }
    }

    const fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64Linux | Self::X86_64LinuxMusl => 62,
            Self::Aarch64Linux | Self::Aarch64LinuxMusl => 183,
        }
    }
}

trait Installer {
    fn install(&self, artifact: &[u8], target: Target) -> Result<InstallReceipt, UpdateError>;
}

#[derive(Debug)]
struct InstallReceipt {
    path: PathBuf,
    retained_rollback_path: Option<PathBuf>,
    cleanup_warning: Option<String>,
}

struct CurrentExecutableInstaller {
    lock: Option<UpdaterLock>,
}

impl CurrentExecutableInstaller {
    fn new(mode: UpdateMode) -> Result<Self, UpdateError> {
        let lock = match mode {
            UpdateMode::CheckOnly => None,
            UpdateMode::Install => Some(UpdaterLock::acquire_current()?),
        };
        Ok(Self { lock })
    }
}

impl Installer for CurrentExecutableInstaller {
    fn install(&self, artifact: &[u8], target: Target) -> Result<InstallReceipt, UpdateError> {
        validate_elf(artifact, target)?;
        let lock = self
            .lock
            .as_ref()
            .ok_or_else(|| UpdateError::Installation {
                reason: "install invoked without the exclusive updater lock".to_owned(),
            })?;
        let executable = lock.executable.clone();
        let replacement = replace_executable(&executable, artifact, lock)?;
        Ok(InstallReceipt {
            path: executable,
            retained_rollback_path: replacement.retained_rollback_path,
            cleanup_warning: replacement.cleanup_warning,
        })
    }
}

#[derive(Debug)]
struct UpdaterLock {
    executable: PathBuf,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    original: std::fs::File,
}

impl UpdaterLock {
    fn acquire_current() -> Result<Self, UpdateError> {
        let executable = std::env::current_exe().map_err(|error| UpdateError::Installation {
            reason: format!("cannot locate the running executable: {error}"),
        })?;
        Self::acquire(&executable)
    }

    #[cfg(target_os = "linux")]
    fn acquire(executable: &Path) -> Result<Self, UpdateError> {
        use std::{
            fs::OpenOptions,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };

        let lock_path = updater_lock_path(executable);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| UpdateError::Installation {
                reason: format!("cannot open updater lock {}: {error}", lock_path.display()),
            })?;
        let path_metadata =
            std::fs::symlink_metadata(&lock_path).map_err(|error| UpdateError::Installation {
                reason: format!(
                    "cannot inspect updater lock {}: {error}",
                    lock_path.display()
                ),
            })?;
        let file_metadata = file.metadata().map_err(|error| UpdateError::Installation {
            reason: format!("cannot inspect open updater lock: {error}"),
        })?;
        if !path_metadata.file_type().is_file()
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(UpdateError::Installation {
                reason: "updater lock path changed while it was opened".to_owned(),
            });
        }
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                UpdateError::UpdateInProgress {
                    lock_path: lock_path.clone(),
                }
            } else {
                UpdateError::Installation {
                    reason: format!("cannot lock {}: {error}", lock_path.display()),
                }
            }
        })?;
        let executable_path_metadata =
            std::fs::symlink_metadata(executable).map_err(|error| UpdateError::Installation {
                reason: format!("cannot inspect {}: {error}", executable.display()),
            })?;
        if !executable_path_metadata.file_type().is_file() {
            return Err(UpdateError::Installation {
                reason: format!(
                    "refusing to update non-regular executable {}",
                    executable.display()
                ),
            });
        }
        let original = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(executable)
            .map_err(|error| UpdateError::Installation {
                reason: format!(
                    "cannot open {} without following links: {error}",
                    executable.display()
                ),
            })?;
        let original_metadata = original
            .metadata()
            .map_err(|error| UpdateError::Installation {
                reason: format!("cannot inspect open executable: {error}"),
            })?;
        if executable_path_metadata.dev() != original_metadata.dev()
            || executable_path_metadata.ino() != original_metadata.ino()
        {
            return Err(UpdateError::ConcurrentExecutableChange);
        }
        Ok(Self {
            executable: executable.to_owned(),
            file,
            original,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn acquire(_executable: &Path) -> Result<Self, UpdateError> {
        Err(UpdateError::UnsupportedPlatform {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            environment: "unknown",
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for UpdaterLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn updater_lock_path(executable: &Path) -> PathBuf {
    use std::ffi::OsString;

    let mut name = OsString::from(".");
    name.push(executable.file_name().unwrap_or_default());
    name.push("-update.lock");
    executable.with_file_name(name)
}

async fn execute<T: Transport, I: Installer>(
    transport: &T,
    installer: &I,
    trust: &TrustConfig,
    target: Target,
    current: &Version,
    mode: UpdateMode,
) -> Result<UpdateOutcome, UpdateError> {
    let release = latest_stable_release(transport, &trust.repository).await?;
    let manifest_url = release_asset_url(&release.release, &trust.repository, MANIFEST_ASSET_NAME)?;
    let signature_url =
        release_asset_url(&release.release, &trust.repository, SIGNATURE_ASSET_NAME)?;
    let manifest_bytes = transport.get(&manifest_url, MAX_MANIFEST_BYTES).await?;
    let signature_bytes = transport.get(&signature_url, MAX_SIGNATURE_BYTES).await?;
    let artifact = authenticate_manifest(
        &manifest_bytes,
        &signature_bytes,
        trust,
        &release.version,
        target,
    )?;

    match artifact.version.cmp(current) {
        std::cmp::Ordering::Less => {
            return Err(UpdateError::DowngradeRefused {
                current: current.clone(),
                offered: artifact.version,
            });
        }
        std::cmp::Ordering::Equal => {
            return Ok(UpdateOutcome {
                current: current.clone(),
                latest: artifact.version,
                status: UpdateStatus::UpToDate,
                installed_path: None,
                retained_rollback_path: None,
                cleanup_warning: None,
            });
        }
        std::cmp::Ordering::Greater => {}
    }

    let binary_url = release_asset_url(&release.release, &trust.repository, &artifact.name)?;
    if mode == UpdateMode::CheckOnly {
        return Ok(UpdateOutcome {
            current: current.clone(),
            latest: artifact.version,
            status: UpdateStatus::Available,
            installed_path: None,
            retained_rollback_path: None,
            cleanup_warning: None,
        });
    }

    let binary = transport.get(&binary_url, MAX_BINARY_BYTES).await?;
    let actual_digest = digest::digest(&digest::SHA256, &binary);
    if actual_digest.as_ref() != artifact.sha256 {
        return Err(UpdateError::DigestMismatch {
            asset: artifact.name,
        });
    }
    let receipt = installer.install(&binary, target)?;
    Ok(UpdateOutcome {
        current: current.clone(),
        latest: artifact.version,
        status: UpdateStatus::Installed,
        installed_path: Some(receipt.path),
        retained_rollback_path: receipt.retained_rollback_path,
        cleanup_warning: receipt.cleanup_warning,
    })
}

fn validate_elf(artifact: &[u8], target: Target) -> Result<(), UpdateError> {
    if artifact.len() < 20
        || artifact.get(..4) != Some(b"\x7fELF")
        || artifact[4] != 2
        || artifact[5] != 1
    {
        return Err(UpdateError::InvalidBinary {
            reason: "asset is not a little-endian ELF64 binary".to_owned(),
        });
    }
    let machine = u16::from_le_bytes([artifact[18], artifact[19]]);
    if machine != target.elf_machine() {
        return Err(UpdateError::InvalidBinary {
            reason: format!(
                "ELF machine {machine} does not match target {}",
                target.triple()
            ),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn replace_executable(
    path: &Path,
    artifact: &[u8],
    lock: &UpdaterLock,
) -> Result<ReplacementReceipt, UpdateError> {
    replace_executable_transaction(path, artifact, Some(&lock.original), &NoInstallFault)
}

#[cfg(not(target_os = "linux"))]
fn replace_executable(
    _path: &Path,
    _artifact: &[u8],
    _lock: &UpdaterLock,
) -> Result<ReplacementReceipt, UpdateError> {
    Err(UpdateError::UnsupportedPlatform {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        environment: "unknown",
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallCheckpoint {
    Staged,
    BackupDurable,
    Replaced,
    Cleanup,
}

#[cfg(target_os = "linux")]
trait InstallFault {
    fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()>;
}

#[cfg(target_os = "linux")]
struct NoInstallFault;

#[derive(Debug, Default)]
struct ReplacementReceipt {
    retained_rollback_path: Option<PathBuf>,
    cleanup_warning: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
impl InstallFault for NoInstallFault {
    fn checkpoint(&self, _checkpoint: InstallCheckpoint) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "the deliberately linear filesystem transaction keeps ordering and cleanup state auditable"
)]
fn replace_executable_transaction<F: InstallFault>(
    path: &Path,
    artifact: &[u8],
    pre_network_original: Option<&std::fs::File>,
    faults: &F,
) -> Result<ReplacementReceipt, UpdateError> {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };

    let parent = path.parent().ok_or_else(|| UpdateError::Installation {
        reason: format!("executable path {} has no parent", path.display()),
    })?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| UpdateError::Installation {
        reason: format!("cannot inspect {}: {error}", path.display()),
    })?;
    if !path_metadata.file_type().is_file() {
        return Err(UpdateError::Installation {
            reason: format!("refusing to replace non-regular file {}", path.display()),
        });
    }
    let original = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| UpdateError::Installation {
            reason: format!(
                "cannot open {} without following links: {error}",
                path.display()
            ),
        })?;
    let metadata = original
        .metadata()
        .map_err(|error| UpdateError::Installation {
            reason: format!("cannot inspect open executable: {error}"),
        })?;
    if let Some(pre_network_original) = pre_network_original {
        let pre_network_metadata =
            pre_network_original
                .metadata()
                .map_err(|error| UpdateError::Installation {
                    reason: format!("cannot inspect pre-network executable: {error}"),
                })?;
        if metadata.dev() != pre_network_metadata.dev()
            || metadata.ino() != pre_network_metadata.ino()
        {
            return Err(UpdateError::ConcurrentExecutableChange);
        }
    }
    if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
        return Err(UpdateError::ConcurrentExecutableChange);
    }
    require_no_extended_attributes(&original)?;

    let (staging_path, mut staging) = create_sibling(path, "staging")?;
    let backup_path = unique_sibling(path, "rollback");
    let mut backup_created = false;
    let mut replacement_started = false;
    let operation = (|| -> Result<(), UpdateError> {
        staging
            .write_all(artifact)
            .map_err(|error| UpdateError::Installation {
                reason: format!("cannot stage {}: {error}", staging_path.display()),
            })?;
        nix::unistd::fchown(
            &staging,
            Some(nix::unistd::Uid::from_raw(metadata.uid())),
            Some(nix::unistd::Gid::from_raw(metadata.gid())),
        )
        .map_err(|error| UpdateError::Installation {
            reason: format!("cannot preserve executable ownership: {error}"),
        })?;
        staging
            .set_permissions(metadata.permissions())
            .and_then(|()| staging.sync_all())
            .map_err(|error| UpdateError::Installation {
                reason: format!("cannot stage {}: {error}", staging_path.display()),
            })?;
        faults
            .checkpoint(InstallCheckpoint::Staged)
            .map_err(|error| UpdateError::Installation {
                reason: format!("staging interrupted: {error}"),
            })?;

        fs::hard_link(path, &backup_path).map_err(|error| UpdateError::Installation {
            reason: format!(
                "cannot create rollback link {}: {error}",
                backup_path.display()
            ),
        })?;
        backup_created = true;
        let backup_metadata =
            fs::metadata(&backup_path).map_err(|error| UpdateError::Installation {
                reason: format!("cannot inspect rollback link: {error}"),
            })?;
        if backup_metadata.dev() != metadata.dev() || backup_metadata.ino() != metadata.ino() {
            return Err(UpdateError::Installation {
                reason: "executable changed while creating rollback material".to_owned(),
            });
        }
        sync_directory(parent)?;
        faults
            .checkpoint(InstallCheckpoint::BackupDurable)
            .map_err(|error| UpdateError::Installation {
                reason: format!("replacement interrupted before rename: {error}"),
            })?;

        let current_open_metadata = original
            .metadata()
            .map_err(|_| UpdateError::ConcurrentExecutableChange)?;
        if current_open_metadata.dev() != metadata.dev()
            || current_open_metadata.ino() != metadata.ino()
            || current_open_metadata.uid() != metadata.uid()
            || current_open_metadata.gid() != metadata.gid()
            || current_open_metadata.mode() != metadata.mode()
            || current_open_metadata.len() != metadata.len()
            || current_open_metadata.mtime() != metadata.mtime()
            || current_open_metadata.mtime_nsec() != metadata.mtime_nsec()
        {
            return Err(UpdateError::ConcurrentExecutableChange);
        }
        require_no_extended_attributes(&original)?;
        let current_path_metadata =
            fs::symlink_metadata(path).map_err(|_| UpdateError::ConcurrentExecutableChange)?;
        if !current_path_metadata.file_type().is_file()
            || current_path_metadata.dev() != metadata.dev()
            || current_path_metadata.ino() != metadata.ino()
        {
            return Err(UpdateError::ConcurrentExecutableChange);
        }

        let replacement_metadata =
            staging
                .metadata()
                .map_err(|error| UpdateError::Installation {
                    reason: format!("cannot inspect staged executable: {error}"),
                })?;
        let replacement_identity = FileIdentity {
            device: replacement_metadata.dev(),
            inode: replacement_metadata.ino(),
        };
        let original_identity = FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        fs::rename(&staging_path, path).map_err(|error| UpdateError::Installation {
            reason: format!("atomic executable replacement failed: {error}"),
        })?;
        replacement_started = true;
        if let Err(error) = faults.checkpoint(InstallCheckpoint::Replaced) {
            return rollback_after_replace(
                path,
                &backup_path,
                parent,
                replacement_identity,
                original_identity,
                format!("replacement interrupted after rename: {error}"),
            );
        }
        if let Err(error) = sync_directory(parent) {
            return rollback_after_replace(
                path,
                &backup_path,
                parent,
                replacement_identity,
                original_identity,
                error.to_string(),
            );
        }

        Ok(())
    })();

    drop(staging);
    if let Err(error) = operation {
        let _ = fs::remove_file(&staging_path);
        if backup_created && !replacement_started {
            let _ = fs::remove_file(&backup_path);
        }
        return Err(error);
    }

    if let Err(error) = faults.checkpoint(InstallCheckpoint::Cleanup) {
        return Ok(ReplacementReceipt {
            retained_rollback_path: Some(backup_path.clone()),
            cleanup_warning: Some(format!(
                "the new executable is durable, but cleanup was interrupted: {error}"
            )),
        });
    }
    match fs::remove_file(&backup_path) {
        Ok(()) => match sync_directory(parent) {
            Ok(()) => Ok(ReplacementReceipt::default()),
            Err(error) => Ok(ReplacementReceipt {
                retained_rollback_path: None,
                cleanup_warning: Some(format!(
                    "the new executable is durable, but fsync after rollback-link removal failed: {error}"
                )),
            }),
        },
        Err(error) => Ok(ReplacementReceipt {
            retained_rollback_path: Some(backup_path.clone()),
            cleanup_warning: Some(format!(
                "the new executable is durable, but the rollback link could not be removed: {error}"
            )),
        }),
    }
}

#[cfg(all(test, target_os = "linux"))]
fn replace_executable_with_faults<F: InstallFault>(
    path: &Path,
    artifact: &[u8],
    faults: &F,
) -> Result<ReplacementReceipt, UpdateError> {
    replace_executable_transaction(path, artifact, None, faults)
}

#[cfg(target_os = "linux")]
fn require_no_extended_attributes(file: &std::fs::File) -> Result<(), UpdateError> {
    let attributes = xattr::FileExt::list_xattr(file)
        .map_err(|error| UpdateError::Installation {
            reason: format!("cannot inspect executable extended attributes: {error}"),
        })?
        .collect::<Vec<_>>();
    if attributes.is_empty() {
        return Ok(());
    }
    Err(UpdateError::UnsupportedExecutableMetadata {
        attributes: attributes
            .iter()
            .map(|name| name.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

#[cfg(target_os = "linux")]
fn rollback_after_replace(
    path: &Path,
    backup_path: &Path,
    parent: &Path,
    replacement_identity: FileIdentity,
    original_identity: FileIdentity,
    cause: String,
) -> Result<(), UpdateError> {
    use std::os::unix::fs::MetadataExt;

    let current = std::fs::symlink_metadata(path).map_err(|error| UpdateError::RollbackFailed {
        cause: cause.clone(),
        rollback: format!("cannot inspect replacement before rollback: {error}"),
    })?;
    if !current.file_type().is_file()
        || current.dev() != replacement_identity.device
        || current.ino() != replacement_identity.inode
    {
        return Err(UpdateError::RollbackFailed {
            cause,
            rollback: "refusing to overwrite a concurrently changed executable path".to_owned(),
        });
    }
    let backup =
        std::fs::symlink_metadata(backup_path).map_err(|error| UpdateError::RollbackFailed {
            cause: cause.clone(),
            rollback: format!("cannot inspect rollback material: {error}"),
        })?;
    if !backup.file_type().is_file()
        || backup.dev() != original_identity.device
        || backup.ino() != original_identity.inode
    {
        return Err(UpdateError::RollbackFailed {
            cause,
            rollback: "refusing unrecognized rollback material".to_owned(),
        });
    }
    std::fs::rename(backup_path, path).map_err(|rollback| UpdateError::RollbackFailed {
        cause: cause.clone(),
        rollback: rollback.to_string(),
    })?;
    sync_directory(parent).map_err(|rollback| UpdateError::RollbackFailed {
        cause: cause.clone(),
        rollback: rollback.to_string(),
    })?;
    Err(UpdateError::InstallationRolledBack { cause })
}

#[cfg(target_os = "linux")]
fn sync_directory(directory: &Path) -> Result<(), UpdateError> {
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| UpdateError::Installation {
            reason: format!("cannot fsync directory {}: {error}", directory.display()),
        })
}

#[cfg(target_os = "linux")]
fn create_sibling(path: &Path, role: &str) -> Result<(PathBuf, std::fs::File), UpdateError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    for _ in 0..32 {
        let candidate = unique_sibling(path, role);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(UpdateError::Installation {
                    reason: format!("cannot create {}: {error}", candidate.display()),
                });
            }
        }
    }
    Err(UpdateError::Installation {
        reason: "cannot allocate a unique staging path".to_owned(),
    })
}

#[cfg(target_os = "linux")]
fn unique_sibling(path: &Path, role: &str) -> PathBuf {
    use std::ffi::OsString;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(
        ".rs-proxy-{role}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    path.with_file_name(name)
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 {
        return Err(format!("expected {} hexadecimal characters", N * 2));
    }
    let mut decoded = [0_u8; N];
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_hex_digit(pair[0])?;
        let low = decode_hex_digit(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex_digit(digit: u8) -> Result<u8, String> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err("value is not hexadecimal".to_owned()),
    }
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(
        "self-update is unavailable: this build has no pinned GitHub repository and Ed25519 public key"
    )]
    TrustNotConfigured,
    #[error("invalid build-pinned GitHub repository {repository:?}; expected owner/repository")]
    InvalidPinnedRepository { repository: String },
    #[error("invalid build-pinned Ed25519 public key: {reason}")]
    InvalidPinnedPublicKey { reason: String },
    #[error(
        "self-update supports Linux GNU or musl on x86_64/aarch64, not {os}/{architecture}/{environment}"
    )]
    UnsupportedPlatform {
        os: &'static str,
        architecture: &'static str,
        environment: &'static str,
    },
    #[error("invalid current package version: {reason}")]
    InvalidCurrentVersion { reason: String },
    #[error("another updater owns the lifecycle lock {lock_path}")]
    UpdateInProgress { lock_path: PathBuf },
    #[error("cannot construct the HTTPS client: {reason}")]
    HttpClient { reason: String },
    #[error("cannot download {url}: {reason}")]
    Download { url: String, reason: String },
    #[error("download {url} exceeds the {maximum_bytes}-byte limit")]
    DownloadTooLarge { url: String, maximum_bytes: usize },
    #[error("invalid GitHub release response: {reason}")]
    InvalidReleaseResponse { reason: String },
    #[error("the pinned repository has no stable SemVer release")]
    NoStableRelease,
    #[error("release scan exceeded the bounded {maximum_pages}-page limit")]
    ReleasePageLimit { maximum_pages: usize },
    #[error("release is missing required asset {name}")]
    MissingReleaseAsset { name: String },
    #[error("release contains duplicate asset {name}")]
    DuplicateReleaseAsset { name: String },
    #[error("release contains an untrusted asset URL: {url}")]
    UntrustedAssetUrl { url: String },
    #[error("manifest signature must be a 64-byte hexadecimal value")]
    InvalidSignatureEncoding,
    #[error("manifest Ed25519 signature verification failed")]
    InvalidManifestSignature,
    #[error("invalid signed manifest: {reason}")]
    InvalidManifest { reason: String },
    #[error("signed manifest repository mismatch: expected {expected}, received {actual}")]
    ManifestRepositoryMismatch { expected: String, actual: String },
    #[error("signed manifest version mismatch: expected {expected}, received {actual}")]
    ManifestVersionMismatch { expected: Version, actual: String },
    #[error("signed manifest has no asset for {target}")]
    ManifestTargetMissing { target: String },
    #[error("refusing authenticated downgrade from {current} to {offered}")]
    DowngradeRefused { current: Version, offered: Version },
    #[error("SHA-256 digest mismatch for authenticated asset {asset}")]
    DigestMismatch { asset: String },
    #[error("invalid update binary: {reason}")]
    InvalidBinary { reason: String },
    #[error("refusing to replace an executable with unsupported extended attributes: {attributes}")]
    UnsupportedExecutableMetadata { attributes: String },
    #[error("the executable changed concurrently; refusing to overwrite the new path")]
    ConcurrentExecutableChange,
    #[error("update installation failed: {reason}")]
    Installation { reason: String },
    #[error("update installation failed and the previous executable was restored: {cause}")]
    InstallationRolledBack { cause: String },
    #[error("update installation failed ({cause}) and rollback also failed ({rollback})")]
    RollbackFailed { cause: String, rollback: String },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        sync::{Arc, Mutex},
    };

    use ring::signature::KeyPair;

    use super::*;

    const REPOSITORY: &str = "trusted-owner/rs-proxy";
    const MANIFEST_URL: &str =
        "https://github.com/trusted-owner/rs-proxy/releases/download/v2.0.0/rs-proxy-manifest.toml";
    const SIGNATURE_URL: &str = "https://github.com/trusted-owner/rs-proxy/releases/download/v2.0.0/rs-proxy-manifest.toml.sig";
    const BINARY_URL: &str =
        "https://github.com/trusted-owner/rs-proxy/releases/download/v2.0.0/rs-proxy-linux-x86_64";
    const TEST_SEED: [u8; 32] = [7; 32];

    #[derive(Clone, Default)]
    struct MemoryTransport {
        responses: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl MemoryTransport {
        fn insert(&self, url: impl Into<String>, body: impl Into<Vec<u8>>) {
            self.responses
                .lock()
                .expect("responses lock")
                .insert(url.into(), body.into());
        }

        fn requested(&self, url: &str) -> bool {
            self.requests
                .lock()
                .expect("requests lock")
                .iter()
                .any(|request| request == url)
        }
    }

    impl Transport for MemoryTransport {
        async fn get(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, UpdateError> {
            tokio::task::yield_now().await;
            self.requests
                .lock()
                .expect("requests lock")
                .push(url.to_owned());
            let body = self
                .responses
                .lock()
                .expect("responses lock")
                .get(url)
                .cloned()
                .ok_or_else(|| UpdateError::Download {
                    url: url.to_owned(),
                    reason: "missing fixture".to_owned(),
                })?;
            if body.len() > maximum_bytes {
                return Err(UpdateError::DownloadTooLarge {
                    url: url.to_owned(),
                    maximum_bytes,
                });
            }
            Ok(body)
        }
    }

    #[derive(Default)]
    struct RecordingInstaller {
        installed: Mutex<Vec<Vec<u8>>>,
    }

    impl Installer for RecordingInstaller {
        fn install(&self, artifact: &[u8], target: Target) -> Result<InstallReceipt, UpdateError> {
            validate_elf(artifact, target)?;
            self.installed
                .lock()
                .expect("installed lock")
                .push(artifact.to_vec());
            Ok(InstallReceipt {
                path: PathBuf::from("/fixture/rs-proxy"),
                retained_rollback_path: None,
                cleanup_warning: None,
            })
        }
    }

    struct Fixture {
        transport: MemoryTransport,
        trust: TrustConfig,
        binary: Vec<u8>,
    }

    impl Fixture {
        fn valid() -> Self {
            let key_pair = test_key_pair();
            let public_key = key_pair
                .public_key()
                .as_ref()
                .try_into()
                .expect("public key size");
            let trust = TrustConfig {
                repository: REPOSITORY.to_owned(),
                public_key,
            };
            let binary = elf_fixture(Target::X86_64Linux);
            let digest = digest::digest(&digest::SHA256, &binary);
            let manifest = signed_manifest(
                REPOSITORY,
                "2.0.0",
                "x86_64-unknown-linux-gnu",
                "rs-proxy-linux-x86_64",
                digest.as_ref(),
            );
            let transport = MemoryTransport::default();
            transport.insert(releases_url(), release_json());
            transport.insert(MANIFEST_URL, manifest.as_bytes());
            transport.insert(
                SIGNATURE_URL,
                encode_hex(test_key_pair().sign(manifest.as_bytes()).as_ref()),
            );
            transport.insert(BINARY_URL, binary.clone());
            Self {
                transport,
                trust,
                binary,
            }
        }

        fn replace_signed_manifest(&self, manifest: &str) {
            self.transport.insert(MANIFEST_URL, manifest.as_bytes());
            self.transport.insert(
                SIGNATURE_URL,
                encode_hex(test_key_pair().sign(manifest.as_bytes()).as_ref()),
            );
        }
    }

    fn test_key_pair() -> signature::Ed25519KeyPair {
        signature::Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).expect("test key pair")
    }

    fn releases_url() -> String {
        format!("https://api.github.com/repos/{REPOSITORY}/releases?per_page=100&page=1")
    }

    fn release_json() -> Vec<u8> {
        release_json_with_binary(BINARY_URL)
    }

    fn release_json_with_binary(binary_url: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "tag_name": "v2.0.0",
            "draft": false,
            "prerelease": false,
            "assets": [
                { "name": MANIFEST_ASSET_NAME, "browser_download_url": MANIFEST_URL },
                { "name": SIGNATURE_ASSET_NAME, "browser_download_url": SIGNATURE_URL },
                { "name": "rs-proxy-linux-x86_64", "browser_download_url": binary_url }
            ]
        }]))
        .expect("release JSON")
    }

    fn signed_manifest(
        repository: &str,
        version: &str,
        target: &str,
        asset: &str,
        sha256: &[u8],
    ) -> String {
        format!(
            "schema = 1\nrepository = {repository:?}\nversion = {version:?}\n\n[[assets]]\ntarget = {target:?}\nname = {asset:?}\nsha256 = \"{}\"\n",
            encode_hex(sha256)
        )
    }

    fn elf_fixture(target: Target) -> Vec<u8> {
        let mut binary = vec![0_u8; 64];
        binary[..4].copy_from_slice(b"\x7fELF");
        binary[4] = 2;
        binary[5] = 1;
        binary[18..20].copy_from_slice(&target.elf_machine().to_le_bytes());
        binary
    }

    fn encode_hex(bytes: &[u8]) -> String {
        use std::fmt::Write;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("write to string");
        }
        encoded
    }

    async fn execute_fixture(
        fixture: &Fixture,
        installer: &RecordingInstaller,
        current: Version,
        mode: UpdateMode,
    ) -> Result<UpdateOutcome, UpdateError> {
        execute(
            &fixture.transport,
            installer,
            &fixture.trust,
            Target::X86_64Linux,
            &current,
            mode,
        )
        .await
    }

    #[test]
    fn missing_or_partial_trust_fails_before_transport_or_filesystem_exist() {
        assert!(matches!(
            TrustConfig::from_options(None, None),
            Err(UpdateError::TrustNotConfigured)
        ));
        assert!(matches!(
            TrustConfig::from_options(Some(REPOSITORY), None),
            Err(UpdateError::TrustNotConfigured)
        ));
        assert!(matches!(
            TrustConfig::from_options(None, Some(&"00".repeat(32))),
            Err(UpdateError::TrustNotConfigured)
        ));
    }

    #[tokio::test]
    async fn default_unconfigured_build_run_fails_closed_in_both_modes() {
        if PINNED_REPOSITORY.is_none() || PINNED_PUBLIC_KEY.is_none() {
            for mode in [UpdateMode::CheckOnly, UpdateMode::Install] {
                assert!(matches!(
                    run(mode).await,
                    Err(UpdateError::TrustNotConfigured)
                ));
            }
        }
    }

    #[test]
    fn malformed_compile_time_trust_and_asset_urls_are_rejected() {
        assert!(matches!(
            TrustConfig::from_options(Some("owner/repo/extra"), Some(&"00".repeat(32))),
            Err(UpdateError::InvalidPinnedRepository { .. })
        ));
        assert!(matches!(
            TrustConfig::from_options(Some(REPOSITORY), Some("not-a-key")),
            Err(UpdateError::InvalidPinnedPublicKey { .. })
        ));
        for url in [
            "http://github.com/trusted-owner/rs-proxy/releases/download/v2/a",
            "https://attacker@github.com/trusted-owner/rs-proxy/releases/download/v2/a",
            "https://github.com:444/trusted-owner/rs-proxy/releases/download/v2/a",
            "https://github.com/other/rs-proxy/releases/download/v2/a",
        ] {
            assert!(matches!(
                validate_asset_url(url, REPOSITORY),
                Err(UpdateError::UntrustedAssetUrl { .. })
            ));
        }
    }

    #[test]
    fn target_selection_accepts_release_targets_and_rejects_other_platforms() {
        assert_eq!(
            Target::from_platform("linux", "x86_64", "gnu").expect("GNU target"),
            Target::X86_64Linux
        );
        assert_eq!(
            Target::from_platform("linux", "x86_64", "musl").expect("x86-64 musl target"),
            Target::X86_64LinuxMusl
        );
        assert_eq!(
            Target::from_platform("linux", "aarch64", "musl").expect("ARM64 musl target"),
            Target::Aarch64LinuxMusl
        );
        for platform in [
            ("linux", "x86_64", "unknown"),
            ("windows", "x86_64", "gnu"),
            ("linux", "riscv64", "gnu"),
        ] {
            assert!(matches!(
                Target::from_platform(platform.0, platform.1, platform.2),
                Err(UpdateError::UnsupportedPlatform { .. })
            ));
        }
    }

    #[tokio::test]
    async fn signed_musl_release_installs_its_binary() {
        let fixture = Fixture::valid();
        let target = Target::X86_64LinuxMusl;
        let binary = elf_fixture(target);
        let digest = digest::digest(&digest::SHA256, &binary);
        fixture.replace_signed_manifest(&signed_manifest(
            REPOSITORY,
            "2.0.0",
            target.triple(),
            "rs-proxy-linux-x86_64",
            digest.as_ref(),
        ));
        fixture.transport.insert(BINARY_URL, binary.as_slice());
        let installer = RecordingInstaller::default();
        let outcome = execute(
            &fixture.transport,
            &installer,
            &fixture.trust,
            target,
            &Version::new(1, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect("install the signed musl asset");
        assert_eq!(outcome.status, UpdateStatus::Installed);
        assert_eq!(*installer.installed.lock().unwrap(), [binary]);
    }

    #[tokio::test]
    async fn check_only_authenticates_manifest_without_binary_download_or_install() {
        let fixture = Fixture::valid();
        let installer = RecordingInstaller::default();
        let outcome = execute_fixture(
            &fixture,
            &installer,
            Version::new(1, 0, 0),
            UpdateMode::CheckOnly,
        )
        .await
        .expect("authenticated check");
        assert_eq!(outcome.status, UpdateStatus::Available);
        assert!(!fixture.transport.requested(BINARY_URL));
        assert!(
            installer
                .installed
                .lock()
                .expect("installed lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn install_verifies_target_digest_and_elf_before_installer() {
        let fixture = Fixture::valid();
        let installer = RecordingInstaller::default();
        let outcome = execute_fixture(
            &fixture,
            &installer,
            Version::new(1, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect("authenticated install");
        assert_eq!(outcome.status, UpdateStatus::Installed);
        assert_eq!(
            installer
                .installed
                .lock()
                .expect("installed lock")
                .as_slice(),
            [fixture.binary]
        );
    }

    #[tokio::test]
    async fn signed_wrong_repository_and_wrong_target_are_rejected() {
        let fixture = Fixture::valid();
        let digest = digest::digest(&digest::SHA256, &fixture.binary);
        fixture.replace_signed_manifest(&signed_manifest(
            "attacker/rs-proxy",
            "2.0.0",
            "x86_64-unknown-linux-gnu",
            "rs-proxy-linux-x86_64",
            digest.as_ref(),
        ));
        let error = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect_err("repository mismatch");
        assert!(matches!(
            error,
            UpdateError::ManifestRepositoryMismatch { .. }
        ));

        let fixture = Fixture::valid();
        fixture.replace_signed_manifest(&signed_manifest(
            REPOSITORY,
            "2.0.0",
            "aarch64-unknown-linux-gnu",
            "rs-proxy-linux-aarch64",
            digest.as_ref(),
        ));
        let error = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect_err("target mismatch");
        assert!(matches!(error, UpdateError::ManifestTargetMissing { .. }));
    }

    #[tokio::test]
    async fn authenticated_downgrade_is_refused_before_binary_download() {
        let fixture = Fixture::valid();
        let error = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(3, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect_err("downgrade");
        assert!(matches!(error, UpdateError::DowngradeRefused { .. }));
        assert!(!fixture.transport.requested(BINARY_URL));
    }

    #[tokio::test]
    async fn malformed_manifest_and_wrong_signature_are_rejected() {
        let fixture = Fixture::valid();
        fixture.replace_signed_manifest("not valid = [toml");
        let malformed = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::CheckOnly,
        )
        .await
        .expect_err("malformed manifest");
        assert!(matches!(malformed, UpdateError::InvalidManifest { .. }));

        let fixture = Fixture::valid();
        fixture.transport.insert(SIGNATURE_URL, "00".repeat(64));
        let unsigned = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::CheckOnly,
        )
        .await
        .expect_err("wrong signature");
        assert!(matches!(unsigned, UpdateError::InvalidManifestSignature));
    }

    #[tokio::test]
    async fn digest_mismatch_never_invokes_installer() {
        let fixture = Fixture::valid();
        fixture.transport.insert(BINARY_URL, b"tampered artifact");
        let installer = RecordingInstaller::default();
        let error = execute_fixture(
            &fixture,
            &installer,
            Version::new(1, 0, 0),
            UpdateMode::Install,
        )
        .await
        .expect_err("digest mismatch");
        assert!(matches!(error, UpdateError::DigestMismatch { .. }));
        assert!(
            installer
                .installed
                .lock()
                .expect("installed lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn check_only_rejects_missing_or_untrusted_binary_asset_without_downloading_it() {
        let fixture = Fixture::valid();
        let digest = digest::digest(&digest::SHA256, &fixture.binary);
        fixture.replace_signed_manifest(&signed_manifest(
            REPOSITORY,
            "2.0.0",
            "x86_64-unknown-linux-gnu",
            "not-in-release",
            digest.as_ref(),
        ));
        let error = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::CheckOnly,
        )
        .await
        .expect_err("missing release asset");
        assert!(matches!(error, UpdateError::MissingReleaseAsset { .. }));

        let fixture = Fixture::valid();
        fixture.transport.insert(
            releases_url(),
            release_json_with_binary("https://attacker.example/rs-proxy"),
        );
        let error = execute_fixture(
            &fixture,
            &RecordingInstaller::default(),
            Version::new(1, 0, 0),
            UpdateMode::CheckOnly,
        )
        .await
        .expect_err("untrusted release asset URL");
        assert!(matches!(error, UpdateError::UntrustedAssetUrl { .. }));
        assert!(!fixture.transport.requested(BINARY_URL));
    }

    #[test]
    fn stable_tag_parser_rejects_drafts_and_prereleases() {
        let release = |tag: &str, draft, prerelease| ApiRelease {
            tag_name: tag.to_owned(),
            draft,
            prerelease,
            assets: Vec::new(),
        };
        assert_eq!(
            stable_tag_version(&release("v2.4.0", false, false)),
            Some(Version::new(2, 4, 0))
        );
        assert_eq!(
            stable_tag_version(&release("v3.0.0-alpha.1", false, false)),
            None
        );
        assert_eq!(stable_tag_version(&release("v9.0.0", true, false)), None);
        assert_eq!(stable_tag_version(&release("v8.0.0", false, true)), None);
    }

    #[tokio::test]
    async fn release_selection_uses_highest_stable_semver_not_api_order() {
        let transport = MemoryTransport::default();
        transport.insert(
            releases_url(),
            serde_json::to_vec(&serde_json::json!([
                { "tag_name": "v1.9.0", "draft": false, "prerelease": false, "assets": [] },
                { "tag_name": "v9.0.0", "draft": true, "prerelease": false, "assets": [] },
                { "tag_name": "v3.0.0-beta.1", "draft": false, "prerelease": false, "assets": [] },
                { "tag_name": "v2.4.0", "draft": false, "prerelease": false, "assets": [] }
            ]))
            .expect("release fixtures"),
        );
        let selected = latest_stable_release(&transport, REPOSITORY)
            .await
            .expect("latest stable release");
        assert_eq!(selected.version, Version::new(2, 4, 0));
    }

    #[cfg(target_os = "linux")]
    struct FailAt(InstallCheckpoint);

    #[cfg(target_os = "linux")]
    impl InstallFault for FailAt {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            if checkpoint == self.0 {
                Err(std::io::Error::other("injected interruption"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct ReplaceAtBackup {
        executable: PathBuf,
        displaced: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl InstallFault for ReplaceAtBackup {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            if checkpoint == InstallCheckpoint::BackupDurable {
                fs::rename(&self.executable, &self.displaced)?;
                fs::write(&self.executable, b"external replacement")?;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct ReplaceAfterRename {
        executable: PathBuf,
        displaced: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl InstallFault for ReplaceAfterRename {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            if checkpoint == InstallCheckpoint::Replaced {
                fs::rename(&self.executable, &self.displaced)?;
                fs::write(&self.executable, b"external replacement")?;
                return Err(std::io::Error::other("injected interruption"));
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct ChmodAtBackup {
        executable: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl InstallFault for ChmodAtBackup {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            use std::os::unix::fs::PermissionsExt;

            if checkpoint == InstallCheckpoint::BackupDurable {
                fs::set_permissions(&self.executable, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct RewriteAtBackup {
        executable: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl InstallFault for RewriteAtBackup {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            if checkpoint == InstallCheckpoint::BackupDurable {
                fs::write(&self.executable, b"external in-place rewrite")?;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct AddXattrAtBackup {
        executable: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl InstallFault for AddXattrAtBackup {
        fn checkpoint(&self, checkpoint: InstallCheckpoint) -> std::io::Result<()> {
            if checkpoint == InstallCheckpoint::BackupDurable {
                xattr::set(&self.executable, "user.rs_proxy_race", b"late")?;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    struct TempFixture {
        directory: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl TempFixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "rs-proxy-updater-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).expect("create fixture directory");
            Self { directory }
        }

        fn executable(&self) -> PathBuf {
            self.directory.join("rs-proxy")
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TempFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).expect("remove fixture directory");
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_only_executable(fixture: &TempFixture, expected: &[u8]) {
        assert_eq!(
            fs::read(fixture.executable()).expect("read executable"),
            expected
        );
        assert_eq!(
            fs::read_dir(&fixture.directory)
                .expect("read fixture directory")
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interruption_before_atomic_replace_preserves_original() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        let error = replace_executable_with_faults(
            &executable,
            b"new binary",
            &FailAt(InstallCheckpoint::BackupDurable),
        )
        .expect_err("interrupted replacement");
        assert!(matches!(error, UpdateError::Installation { .. }));
        assert_only_executable(&fixture, b"old binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_lock_serializes_updates_and_accepts_an_unlocked_stale_file() {
        use std::os::unix::fs::MetadataExt;

        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        let lock_path = updater_lock_path(&executable);
        assert_eq!(
            lock_path.file_name(),
            Some(std::ffi::OsStr::new(".rs-proxy-update.lock"))
        );
        let first = UpdaterLock::acquire(&executable).expect("first lifecycle lock");
        let error = UpdaterLock::acquire(&executable).expect_err("concurrent updater");
        assert!(matches!(error, UpdateError::UpdateInProgress { .. }));
        let stale_metadata = fs::metadata(&lock_path).expect("locked lifecycle file");
        drop(first);
        assert!(lock_path.is_file());
        let reused =
            UpdaterLock::acquire(&executable).expect("unlocked stale lock file is reusable");
        let reused_metadata = reused.file.metadata().expect("reused lifecycle file");
        assert_eq!(reused_metadata.dev(), stale_metadata.dev());
        assert_eq!(reused_metadata.ino(), stale_metadata.ino());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_replaced_during_download_is_never_overwritten() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        let displaced = fixture.directory.join("pre-network-executable");
        fs::write(&executable, b"old binary").expect("write old binary");
        let installer = CurrentExecutableInstaller {
            lock: Some(UpdaterLock::acquire(&executable).expect("installer lifecycle lock")),
        };

        fs::rename(&executable, &displaced).expect("replace executable during download");
        fs::write(&executable, b"external replacement").expect("write external replacement");
        let error = installer
            .install(&elf_fixture(Target::X86_64Linux), Target::X86_64Linux)
            .expect_err("pre-network inode change must abort installation");

        assert!(matches!(error, UpdateError::ConcurrentExecutableChange));
        assert_eq!(
            fs::read(&executable).expect("read external replacement"),
            b"external replacement"
        );
        assert_eq!(
            fs::read(&displaced).expect("read displaced original"),
            b"old binary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_executable_replacement_is_never_overwritten() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        let displaced = fixture.directory.join("externally-displaced");
        fs::write(&executable, b"old binary").expect("write old binary");
        let error = replace_executable_with_faults(
            &executable,
            b"updater binary",
            &ReplaceAtBackup {
                executable: executable.clone(),
                displaced,
            },
        )
        .expect_err("concurrent replacement");
        assert!(matches!(error, UpdateError::ConcurrentExecutableChange));
        assert_eq!(
            fs::read(&executable).expect("read external replacement"),
            b"external replacement"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_inode_mode_change_before_rename_is_never_overwritten() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o751))
            .expect("set initial mode");
        let error = replace_executable_with_faults(
            &executable,
            b"updater binary",
            &ChmodAtBackup {
                executable: executable.clone(),
            },
        )
        .expect_err("same-inode metadata change");
        assert!(matches!(error, UpdateError::ConcurrentExecutableChange));
        assert_eq!(
            fs::metadata(&executable).expect("changed metadata").mode() & 0o7777,
            0o700
        );
        assert_only_executable(&fixture, b"old binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_inode_content_change_before_rename_is_never_overwritten() {
        use std::os::unix::fs::MetadataExt;

        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        let original_inode = fs::metadata(&executable).expect("original metadata").ino();
        let error = replace_executable_with_faults(
            &executable,
            b"updater binary",
            &RewriteAtBackup {
                executable: executable.clone(),
            },
        )
        .expect_err("same-inode content change");
        assert!(matches!(error, UpdateError::ConcurrentExecutableChange));
        assert_eq!(
            fs::metadata(&executable).expect("rewritten metadata").ino(),
            original_inode
        );
        assert_only_executable(&fixture, b"external in-place rewrite");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_inode_xattr_added_before_rename_is_never_lost() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        if let Err(error) = xattr::set(&executable, "user.rs_proxy_probe", b"probe") {
            eprintln!("SKIP: filesystem cannot create a test xattr: {error}");
            return;
        }
        xattr::remove(&executable, "user.rs_proxy_probe").expect("remove xattr probe");
        let error = replace_executable_with_faults(
            &executable,
            b"updater binary",
            &AddXattrAtBackup {
                executable: executable.clone(),
            },
        )
        .expect_err("same-inode xattr change");
        assert!(matches!(
            error,
            UpdateError::UnsupportedExecutableMetadata { .. }
        ));
        assert_eq!(
            xattr::get(&executable, "user.rs_proxy_race").expect("read late xattr"),
            Some(b"late".to_vec())
        );
        assert_only_executable(&fixture, b"old binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failure_after_atomic_replace_rolls_back_original() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        let error = replace_executable_with_faults(
            &executable,
            b"new binary",
            &FailAt(InstallCheckpoint::Replaced),
        )
        .expect_err("replacement must report rollback");
        assert!(matches!(error, UpdateError::InstallationRolledBack { .. }));
        assert_only_executable(&fixture, b"old binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_never_overwrites_a_concurrent_post_rename_replacement() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        let displaced = fixture.directory.join("updater-displaced");
        fs::write(&executable, b"old binary").expect("write old binary");
        let error = replace_executable_with_faults(
            &executable,
            b"updater binary",
            &ReplaceAfterRename {
                executable: executable.clone(),
                displaced: displaced.clone(),
            },
        )
        .expect_err("concurrent replacement must prevent rollback overwrite");
        assert!(matches!(error, UpdateError::RollbackFailed { .. }));
        assert_eq!(
            fs::read(&executable).expect("read external replacement"),
            b"external replacement"
        );
        assert_eq!(
            fs::read(&displaced).expect("read displaced updater binary"),
            b"updater binary"
        );
        let rollback = fs::read_dir(&fixture.directory)
            .expect("read fixture directory")
            .map(|entry| entry.expect("fixture entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().contains("rs-proxy-rollback"))
            })
            .expect("retained rollback material");
        assert_eq!(fs::read(rollback).expect("read rollback"), b"old binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_commit_cleanup_failure_reports_installed_with_recovery_link() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        let receipt = replace_executable_with_faults(
            &executable,
            b"new binary",
            &FailAt(InstallCheckpoint::Cleanup),
        )
        .expect("durable replacement");
        assert_eq!(
            fs::read(&executable).expect("read executable"),
            b"new binary"
        );
        let rollback = receipt
            .retained_rollback_path
            .expect("retained rollback path");
        assert_eq!(fs::read(&rollback).expect("read rollback"), b"old binary");
        assert!(receipt.cleanup_warning.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_replace_is_atomic_and_preserves_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o4751))
            .expect("set fixture mode");
        let original = fs::metadata(&executable).expect("original metadata");
        let receipt = replace_executable_with_faults(&executable, b"new binary", &NoInstallFault)
            .expect("replace executable");
        assert!(receipt.retained_rollback_path.is_none());
        assert!(receipt.cleanup_warning.is_none());
        assert_eq!(
            fs::metadata(&executable)
                .expect("executable metadata")
                .uid(),
            original.uid()
        );
        assert_eq!(
            fs::metadata(&executable)
                .expect("executable metadata")
                .gid(),
            original.gid()
        );
        assert_eq!(
            fs::metadata(&executable)
                .expect("executable metadata")
                .mode()
                & 0o7777,
            0o4751
        );
        assert_only_executable(&fixture, b"new binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_extended_attributes_are_rejected_instead_of_lost() {
        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        if let Err(error) = xattr::set(&executable, "user.rs_proxy_test", b"present") {
            eprintln!("SKIP: filesystem cannot create a test xattr: {error}");
            return;
        }
        let error = replace_executable_with_faults(&executable, b"new binary", &NoInstallFault)
            .expect_err("xattrs must fail closed");
        assert!(matches!(
            error,
            UpdateError::UnsupportedExecutableMetadata { .. }
        ));
        assert_eq!(
            fs::read(&executable).expect("read executable"),
            b"old binary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_file_capabilities_are_rejected_instead_of_lost() {
        // Linux VFS capability revision 2 with effective CAP_NET_BIND_SERVICE.
        const CAP_NET_BIND_SERVICE: [u8; 20] = [
            0x01, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let fixture = TempFixture::new();
        let executable = fixture.executable();
        fs::write(&executable, b"old binary").expect("write old binary");
        if let Err(error) = xattr::set(&executable, "security.capability", &CAP_NET_BIND_SERVICE) {
            eprintln!("SKIP: process/filesystem cannot create a file capability: {error}");
            return;
        }
        let error = replace_executable_with_faults(&executable, b"new binary", &NoInstallFault)
            .expect_err("file capabilities must fail closed");
        match error {
            UpdateError::UnsupportedExecutableMetadata { attributes } => {
                assert!(
                    attributes
                        .split(", ")
                        .any(|name| name == "security.capability")
                );
            }
            other => panic!("unexpected updater error: {other}"),
        }
        assert_eq!(
            fs::read(&executable).expect("read executable"),
            b"old binary"
        );
    }
}
