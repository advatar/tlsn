use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use tlsn_browser_demo::{AppConfig, DestinationPolicy, app};
use tlsn_sdk_core::VerifierConfig;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Run the TLSNotary browser demo server.")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    #[arg(long)]
    static_dir: Option<PathBuf>,
    #[arg(long)]
    wasm_pkg_dir: Option<PathBuf>,
    #[arg(long = "allow-host")]
    allow_hosts: Vec<String>,
    #[arg(long = "allow-port", default_values_t = [443])]
    allow_ports: Vec<u16>,
    #[arg(long)]
    allow_loopback: bool,
    #[arg(long)]
    allow_private_ips: bool,
    #[arg(long, default_value_t = 16 * 1024)]
    verifier_max_sent_data: usize,
    #[arg(long, default_value_t = 256 * 1024)]
    verifier_max_recv_data: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = AppConfig {
        static_dir: cli.static_dir.unwrap_or_else(AppConfig::default_static_dir),
        wasm_pkg_dir: cli.wasm_pkg_dir.unwrap_or_else(AppConfig::default_wasm_pkg_dir),
        destination_policy: DestinationPolicy {
            allowed_hosts: cli.allow_hosts,
            allowed_ports: BTreeSet::from_iter(cli.allow_ports),
            allow_loopback: cli.allow_loopback,
            allow_private_ips: cli.allow_private_ips,
        },
        verifier_config: VerifierConfig::builder()
            .max_sent_data(cli.verifier_max_sent_data)
            .max_recv_data(cli.verifier_max_recv_data)
            .build(),
    };

    let listener = TcpListener::bind(cli.listen).await?;
    info!(
        "browser demo listening on http://{} with static={} wasm_pkg={}",
        cli.listen,
        config.static_dir.display(),
        config.wasm_pkg_dir.display()
    );

    axum::serve(listener, app(config)).await?;

    Ok(())
}

