//! Black box tests of the gateway TCP listener: TLS 1.3 only, ALPN, legacy rejection,
//! certificate fingerprint and the channel bound LNEx v3 handshake.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vnox_gateway::net::handshake::{LNEX_VERSION, client_auth_transcript, server_hello_transcript};
use vnox_gateway::proto::{AuthPayload, ErrorCode, ErrorPayload, HelloPayload, PacketId};
use vnox_gateway::tls::{ALPN, EXPORTER_LABEL, spki_fingerprint};

struct Server {
    task: tokio::task::JoinHandle<()>,
    port: u16,
    directory: std::path::PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start() -> Server {
    let directory = std::env::temp_dir().join(format!("vnox-tls-it-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let port = free_port();
    let config = format!(
        r#"
[node]
name = "tls-test"
address = "127.0.0.1"
[gateway]
bind = "127.0.0.1:{port}"
admin_bind = "127.0.0.1:0"
[voice]
bind = "127.0.0.1:0"
[storage]
data_dir = "{dir}"
backend = "sqlite"
sqlite_path = "{dir}/t.db"
[server]
mode = "private"
"#,
        dir = directory.display()
    );
    let cfg: vnox_gateway::domain::config::Config = toml::from_str(&config).unwrap();
    let task = tokio::spawn(async move {
        let _ = vnox_gateway::run(Arc::new(cfg), None).await;
    });
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Server {
                task,
                port,
                directory,
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("gateway did not start");
}

/// Accepts every certificate (the tests pin the fingerprint themselves) but still checks
/// the TLS 1.3 handshake signature.
#[derive(Debug)]
struct AcceptAll {
    leaf: Mutex<Option<Vec<u8>>>,
}
impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: bool,
) -> (rustls::ClientConfig, Arc<AcceptAll>) {
    let verifier = Arc::new(AcceptAll {
        leaf: Mutex::new(None),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier.clone())
    .with_no_client_auth();
    if alpn {
        config.alpn_protocols = vec![ALPN.to_vec()];
    }
    (config, verifier)
}

async fn connect_tls(
    server: &Server,
    config: rustls::ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).await?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
}

async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> (u16, u32, Vec<u8>) {
    let mut header = [0u8; 12];
    stream.read_exact(&mut header).await.unwrap();
    let id = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    assert_eq!(flags, 0);
    let sequence = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let length = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await.unwrap();
    (id, sequence, payload)
}

fn frame(id: PacketId, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(id as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn tls13_with_alpn_works_and_certificate_fingerprint_matches_the_published_one() {
    let server = start().await;
    let (config, verifier) = client_config(&[&rustls::version::TLS13], true);
    let tls = connect_tls(&server, config).await.unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ALPN));
    let leaf = verifier.leaf.lock().unwrap().clone().unwrap();
    let seen = hex::encode(spki_fingerprint(&leaf).unwrap());
    let published =
        std::fs::read_to_string(server.directory.join("tls").join("fingerprint.txt")).unwrap();
    assert_eq!(seen, published.trim());
}

#[tokio::test]
async fn tls12_only_client_is_rejected() {
    let server = start().await;
    let (config, _) = client_config(&[&rustls::version::TLS12], true);
    let result = connect_tls(&server, config).await;
    assert!(result.is_err(), "the listener must not negotiate TLS 1.2");
}

#[tokio::test]
async fn client_without_alpn_is_rejected_before_any_lnex_byte() {
    let server = start().await;
    let (config, _) = client_config(&[&rustls::version::TLS13], false);
    match connect_tls(&server, config).await {
        Err(_) => {}
        Ok(mut tls) => {
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut byte)).await;
            assert!(
                !matches!(read, Ok(Ok(n)) if n > 0),
                "no LNEx data may be sent without ALPN vnox-lnex/3"
            );
        }
    }
}

#[tokio::test]
async fn plaintext_garbage_gets_explicit_version_error() {
    let server = start().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    tcp.write_all(&frame(PacketId::Auth, 0, b"old client"))
        .await
        .unwrap();
    let (id, _, payload) = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut tcp))
        .await
        .unwrap();
    assert_eq!(id, PacketId::Error as u16);
    let error = ErrorPayload::decode(payload.as_slice()).unwrap();
    assert_eq!(error.code, ErrorCode::VersionMismatch as u32);
    assert!(error.message.contains("TLS 1.3"));
    let mut rest = Vec::new();
    tcp.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "connection is closed after the error");
}

#[tokio::test]
async fn silent_v2_style_client_gets_explicit_version_error() {
    // An LNEx v2 client waits for the server HELLO and sends nothing.
    let server = start().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    let (id, _, payload) = tokio::time::timeout(Duration::from_secs(8), read_frame(&mut tcp))
        .await
        .unwrap();
    assert_eq!(id, PacketId::Error as u16);
    let error = ErrorPayload::decode(payload.as_slice()).unwrap();
    assert_eq!(error.code, ErrorCode::VersionMismatch as u32);
    assert!(error.message.contains("LNEx v3"));
}

async fn authenticate(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    signing_binding: Option<[u8; 32]>,
) -> (u16, Vec<u8>) {
    let binding = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 32], EXPORTER_LABEL, None)
        .unwrap();
    let (id, sequence, payload) = read_frame(tls).await;
    assert_eq!((id, sequence), (PacketId::Hello as u16, 0));
    let mut hello = HelloPayload::decode(payload.as_slice()).unwrap();
    assert_eq!(hello.lnex_version, LNEX_VERSION);
    // The server HELLO is signed over this connection's exporter.
    let signature = ed25519_dalek::Signature::from_slice(&hello.server_signature).unwrap();
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&hello.server_pubkey.clone().try_into().unwrap())
            .unwrap();
    hello.server_signature.clear();
    verifying
        .verify_strict(
            &server_hello_transcript(&binding, &hello.encode_to_vec()),
            &signature,
        )
        .unwrap();
    let key = SigningKey::generate(&mut rand::rng());
    let mut auth = AuthPayload {
        client_pubkey: key.verifying_key().to_bytes().to_vec(),
        nickname: "tls-test".into(),
        lnex_version: LNEX_VERSION.into(),
        signature: Vec::new(),
    };
    let signed_with = signing_binding.unwrap_or(binding);
    let transcript = client_auth_transcript(&signed_with, &payload, &auth.encode_to_vec());
    auth.signature = key.sign(&transcript).to_bytes().to_vec();
    tls.write_all(&frame(PacketId::Auth, 0, &auth.encode_to_vec()))
        .await
        .unwrap();
    let (id, _, payload) = read_frame(tls).await;
    (id, payload)
}

#[tokio::test]
async fn full_handshake_over_tls_creates_a_session() {
    let server = start().await;
    let (config, _) = client_config(&[&rustls::version::TLS13], true);
    let mut tls = connect_tls(&server, config).await.unwrap();
    let (id, _) = authenticate(&mut tls, None).await;
    assert_eq!(id, PacketId::Session as u16);
}

#[tokio::test]
async fn auth_signed_for_another_tls_connection_is_rejected() {
    let server = start().await;
    let (config, _) = client_config(&[&rustls::version::TLS13], true);
    let mut tls = connect_tls(&server, config).await.unwrap();
    let (id, payload) = authenticate(&mut tls, Some([0x42; 32])).await;
    assert_eq!(id, PacketId::Error as u16);
    let error = ErrorPayload::decode(payload.as_slice()).unwrap();
    assert_eq!(error.code, ErrorCode::AuthFailed as u32);
}
