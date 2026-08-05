use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;
use base64::Engine as _;
use clap::Parser;
use tlsn_browser_demo::{AppConfig, DestinationPolicy, app};
use tlsn_notary_artifact::ArtifactSigner;
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
    /// Persistent 32-byte P-256 secret scalar encoded as 64 hex characters.
    #[arg(long, env = "TLSN_NOTARY_SIGNING_KEY")]
    artifact_signing_key: Option<String>,
    /// Optional 32-byte seed (64 hex chars) that deterministically derives the ML-DSA-65 keypair.
    /// When set, artifacts carry a hybrid post-quantum signature alongside ES256.
    #[arg(long, env = "TLSN_NOTARY_PQ_SEED")]
    pq_signing_seed: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let artifact_signer = match cli.artifact_signing_key {
        Some(value) => ArtifactSigner::from_bytes(&hex::decode(value)?)?,
        None => {
            tracing::warn!(
                "using an ephemeral artifact signing key; set TLSN_NOTARY_SIGNING_KEY in production"
            );
            ArtifactSigner::random()
        }
    };

    let pq_keypair = match cli.pq_signing_seed {
        Some(value) => {
            let bytes = hex::decode(value.trim())?;
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("TLSN_NOTARY_PQ_SEED must be exactly 32 bytes (64 hex chars)")
            })?;
            let (secret, public) = tlsn_notary_artifact::generate_pq_keypair(&seed);
            info!(
                "hybrid post-quantum signing enabled (ML-DSA-65); pq public key hex={} base64url={}",
                hex::encode(&public),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public),
            );
            Some((secret, public))
        }
        None => {
            tracing::warn!(
                "post-quantum signing disabled; set TLSN_NOTARY_PQ_SEED to emit hybrid attestations"
            );
            None
        }
    };

    let config = AppConfig {
        static_dir: cli.static_dir.unwrap_or_else(AppConfig::default_static_dir),
        wasm_pkg_dir: cli
            .wasm_pkg_dir
            .unwrap_or_else(AppConfig::default_wasm_pkg_dir),
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
        artifact_signer,
        pq_keypair,
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
