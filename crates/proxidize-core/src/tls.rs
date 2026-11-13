//! TLS client settings: the IP check and HTTPS proxies. Certificates are checked against the Mozilla roots unless a
//! proxy is set to skip the check (self-signed certificates on your own proxy).

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// `verify`: check the certificate chain and host name (the default); otherwise accept any certificate, while still
/// requiring the handshake signatures to be valid.
pub fn client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    static VERIFIED: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static UNVERIFIED: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let slot = if verify { &VERIFIED } else { &UNVERIFIED };
    slot.get_or_init(|| {
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions");
        let config = if verify {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider()))).with_no_client_auth()
        };
        Arc::new(config)
    })
    .clone()
}

/// The server name to send and check: a host name, or an IP address.
pub fn server_name(host: &str) -> Option<ServerName<'static>> {
    ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string()).ok()
}

#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
