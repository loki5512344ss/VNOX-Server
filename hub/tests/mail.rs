use vnox_hub::{
    config::{SmtpConfig, parse_origin},
    mail::{
        Mailer,
        templates::{self, Kind},
    },
};

#[test]
fn mail_links_stay_on_configured_origin_and_escape_dynamic_content() {
    let origin = parse_origin("https://central.loki-code.dev").unwrap();
    let email = templates::render(
        &origin,
        Kind::Verify {
            token: "abc\"&<https://evil.example>",
        },
    )
    .unwrap();
    assert!(
        email
            .html
            .contains("https://central.loki-code.dev/verify-email?token=")
    );
    assert!(!email.html.contains("href=\"https://evil.example"));
    assert!(!email.html.contains("token=abc\""));
    let email = templates::render(
        &origin,
        Kind::NewDevice {
            device: "<img src=x onerror=evil()>",
        },
    )
    .unwrap();
    assert!(email.html.contains("&lt;img src=x onerror=evil()&gt;"));
    assert!(!email.html.contains("<img src=x"));
    assert!(email.text.contains("<img src=x onerror=evil()>"));
}

#[test]
fn login_codes_are_validated_and_rendered_in_both_message_parts() {
    let origin = parse_origin("https://central.loki-code.dev").unwrap();
    for code in ["123", "1234567x", "123456789", "１２３４５６７８"] {
        assert!(templates::render(&origin, Kind::Login { code }).is_err());
    }
    let email = templates::render(&origin, Kind::Login { code: "12345678" }).unwrap();
    assert!(email.html.contains("12345678"));
    assert!(email.text.contains("12345678"));
    assert!(email.html.contains("10 минут"));
    assert!(email.subject.starts_with("Vnox"));
}

#[test]
fn previews_are_three_safe_html_and_text_pairs() {
    let directory = tempfile::TempDir::new().unwrap();
    let origin = parse_origin("https://central.loki-code.dev").unwrap();
    templates::write_previews(directory.path(), &origin).unwrap();
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 6);
    let verify = std::fs::read_to_string(directory.path().join("verify.html")).unwrap();
    assert!(verify.contains("DUMMY_PREVIEW_NOT_A_REAL_TOKEN"));
    assert!(!verify.contains("LoVisual"));
}

#[test]
fn smtp_setup_rejects_invalid_mailbox_and_tls_hostname() {
    let config = SmtpConfig {
        host: "smtp.example".into(),
        port: 587,
        user: "".into(),
        password: "".into(),
        from: "bad\r\nInjected: x".into(),
    };
    assert!(Mailer::new(&config).is_err());
}

#[tokio::test]
async fn smtp_probe_requires_tls_and_never_falls_back_to_cleartext_authentication() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket
            .write_all(b"220 localhost ESMTP test\r\n")
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        let len = socket.read(&mut buffer).await.unwrap();
        let first = String::from_utf8_lossy(&buffer[..len]).to_string();
        socket
            .write_all(b"250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
            .await
            .unwrap();
        let second = socket.read(&mut buffer).await.unwrap_or(0);
        (first, buffer[..second].to_vec())
    });
    let mailer = Mailer::new(&SmtpConfig {
        host: "localhost".into(),
        port,
        user: "user".into(),
        password: "test-password".into(),
        from: "Vnox <noreply@example.com>".into(),
    })
    .unwrap();
    assert!(mailer.check_connection().await.is_err());
    let (first, second) = server.await.unwrap();
    assert!(first.to_uppercase().starts_with("EHLO"));
    let commands = String::from_utf8_lossy(&second).to_uppercase();
    assert!(!commands.contains("AUTH"));
    assert!(!commands.contains("MAIL FROM"));
}
