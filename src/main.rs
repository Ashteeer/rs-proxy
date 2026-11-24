use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rs_proxy::{
    config::{Config, DEFAULT_CONFIG_PATH, LogFormat},
    server::{ProxyServer, shutdown_signal},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rs-proxy", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the proxy until SIGINT or SIGTERM.
    Run {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Inspect and validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Check for or install an authenticated update from the build-pinned repository.
    Update {
        /// Check for an authenticated newer release without replacing the binary.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Parse the entire file and enforce runtime invariants.
    Validate {
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run_cli().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_cli() -> Result<()> {
    match Cli::parse().command {
        Command::Run { config } => {
            let config = Config::load(&config)?;
            init_logging(config.server.log_level.as_str(), config.server.log_format)?;
            let server = ProxyServer::bind(&config).await?;
            for address in server.local_addresses() {
                info!(listen = %address, "bound listener");
            }
            server.serve_until(shutdown_signal()).await?;
        }
        Command::Config {
            command: ConfigCommand::Validate { config },
        } => {
            Config::load(&config).with_context(|| {
                format!("configuration validation failed: {}", config.display())
            })?;
            println!("valid: {}", config.display());
        }
        Command::Update { check } => {
            let outcome = rs_proxy::update::run(if check {
                rs_proxy::update::UpdateMode::CheckOnly
            } else {
                rs_proxy::update::UpdateMode::Install
            })
            .await?;
            println!("{outcome}");
        }
    }
    Ok(())
}

fn init_logging(level: &str, format: LogFormat) -> Result<()> {
    let filter = EnvFilter::try_new(level)?;
    match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        LogFormat::Compact => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .try_init()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_check_flag_is_part_of_the_cli_contract() {
        let cli =
            Cli::try_parse_from(["rs-proxy", "update", "--check"]).expect("parse update --check");
        assert!(matches!(cli.command, Command::Update { check: true }));
    }
}
