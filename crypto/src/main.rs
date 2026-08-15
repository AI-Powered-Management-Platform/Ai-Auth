//! The Guard's process. Startup is fail-closed: no certificates, no server —
//! plaintext gRPC is not a supported mode, including local development.

use std::net::SocketAddr;

use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use aiauth_crypto::gen::aiauth::crypto::v1::crypto_service_server::CryptoServiceServer;
use aiauth_crypto::service::Guard;

fn required_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("{{\"fatal\":\"missing required environment\",\"var\":\"{name}\"}}");
            std::process::exit(1);
        }
    }
}

fn must_read(path: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{{\"fatal\":\"cannot read credential file\",\"path\":\"{path}\",\"err\":\"{e}\"}}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = std::env::var("CRYPTO_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
        .parse()?;

    // All three are mandatory. There is no flag that skips this.
    let ca = must_read(&required_env("CRYPTO_CA_FILE"));
    let cert = must_read(&required_env("CRYPTO_CERT_FILE"));
    let key = must_read(&required_env("CRYPTO_KEY_FILE"));

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        // Setting a client CA root makes client certificates REQUIRED —
        // mutual TLS, not optional TLS.
        .client_ca_root(Certificate::from_pem(ca));

    println!("{{\"event\":\"guard_up\",\"addr\":\"{addr}\",\"mtls\":true}}");

    Server::builder()
        .tls_config(tls)?
        .add_service(CryptoServiceServer::new(Guard))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            println!("{{\"event\":\"guard_shutdown\"}}");
        })
        .await?;

    Ok(())
}
