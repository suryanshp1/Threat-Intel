use rustls_pki_types::pem::PemObject;
use tokio_postgres::config::SslMode;

/// Require authenticated encryption, or explicitly retain private-network plaintext.
pub fn manager(mut config: tokio_postgres::Config) -> Result<deadpool_postgres::Manager, String> {
    let mode = std::env::var("VI_DB_TLS_MODE").unwrap_or_else(|_| "disable".into());
    let ca = std::env::var("VI_DB_TLS_CA_FILE")
        .ok()
        .filter(|s| !s.is_empty());
    validate(&mode, config.get_ssl_mode(), ca.is_some())?;
    if mode == "disable" {
        config.ssl_mode(SslMode::Disable);
        return Ok(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = ca {
        let bytes = std::fs::read(path).map_err(|_| "Cannot read database CA file")?;
        if bytes.len() > 1024 * 1024 {
            return Err("Database CA file exceeds 1 MiB".into());
        }
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(bytes.as_slice()) {
            roots
                .add(cert.map_err(|_| "Invalid database CA PEM")?)
                .map_err(|_| "Invalid database CA certificate")?;
        }
    } else {
        for cert in rustls_native_certs::load_native_certs().certs {
            roots
                .add(cert)
                .map_err(|_| "Invalid system CA certificate")?;
        }
    }
    if roots.is_empty() {
        return Err("No trusted database CA certificates".into());
    }
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "Invalid database TLS protocol configuration")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.ssl_mode(SslMode::Require);
    Ok(deadpool_postgres::Manager::new(
        config,
        tokio_postgres_rustls::MakeRustlsConnect::new(tls),
    ))
}
fn validate(mode: &str, ssl: SslMode, custom_ca: bool) -> Result<(), String> {
    match mode {
        "disable" if ssl == SslMode::Require || custom_ca => {
            Err("Database TLS requested: set VI_DB_TLS_MODE=verify-full".into())
        }
        "disable" | "verify-full" => Ok(()),
        _ => Err(
            "VI_DB_TLS_MODE must be disable or verify-full; insecure TLS modes are unsupported"
                .into(),
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_configuration_cannot_silently_downgrade() {
        assert!(validate("disable", SslMode::Require, false).is_err());
        assert!(validate("disable", SslMode::Prefer, true).is_err());
        assert!(validate("require", SslMode::Prefer, false).is_err());
        assert!(validate("verify-full", SslMode::Prefer, true).is_ok());
        assert!(validate("disable", SslMode::Prefer, false).is_ok());
    }
}
