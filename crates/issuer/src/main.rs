use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use p256::ecdsa::SigningKey;
use tlsn_issuer::{IssuerConfig, app};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "TLSNotary OpenID4VCI issuer adapter")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:3030")]
    listen: SocketAddr,
    #[arg(long, default_value = "http://127.0.0.1:3030")]
    issuer: String,
    #[arg(long, env = "TLSN_TRUSTED_NOTARY_KEY")]
    trusted_notary_key: String,
    #[arg(long, env = "TLSN_ISSUER_SIGNING_KEY")]
    issuer_signing_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let trusted_notary_key =
        hex::decode(cli.trusted_notary_key).context("invalid trusted notary key hex")?;
    let issuer_key =
        hex::decode(cli.issuer_signing_key).context("invalid issuer signing key hex")?;
    let signing_key =
        SigningKey::from_slice(&issuer_key).context("invalid P-256 issuer signing key")?;
    let listener = TcpListener::bind(cli.listen).await?;
    info!("OpenID4VCI issuer listening at {}", cli.issuer);
    axum::serve(
        listener,
        app(IssuerConfig {
            issuer: cli.issuer.trim_end_matches('/').to_string(),
            trusted_notary_key,
            signing_key,
        }),
    )
    .await?;
    Ok(())
}
