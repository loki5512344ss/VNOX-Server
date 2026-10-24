use anyhow::{Result, bail};
use url::Url;

use super::layout::{self, Content, Lang, Link};
use crate::config::parse_origin;

/// A rendered transactional message; no recipient or delivery happens here.
pub struct Email {
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub enum Kind<'a> {
    Verify { token: &'a str },
    Login { code: &'a str },
    NewDevice { device: &'a str },
}

pub fn render(origin: &Url, kind: Kind<'_>) -> Result<Email> {
    parse_origin(origin.as_str())?;
    let (title, paragraphs, code, button, path, expiry) = match kind {
        Kind::Verify { token } => {
            if token.is_empty() || token.len() > 512 {
                bail!("invalid verification token length");
            }
            (
                "Подтверди свою почту",
                vec!["Добро пожаловать в Vnox!".to_owned(), "Подтверди адрес, чтобы завершить настройку профиля и пользоваться глобальными функциями.".to_owned()],
                None,
                "Подтвердить почту",
                ("verify-email", Some(("token", token))),
                "Ссылка действует 24 часа и может быть использована только один раз.",
            )
        }
        Kind::Login { code } => {
            if code.len() != 8 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("login code must contain exactly eight ASCII digits");
            }
            (
                "Ваш код входа",
                vec![
                    "Используйте этот одноразовый код, чтобы войти в Vnox. Никому его не сообщайте."
                        .to_owned(),
                ],
                Some(code),
                "Открыть Vnox",
                ("login", None),
                "Код действует 10 минут. Он не продлевается при повторном открытии письма.",
            )
        }
        Kind::NewDevice { device } => {
            if device.is_empty() || device.len() > 200 || device.chars().any(char::is_control) {
                bail!("invalid device description");
            }
            (
                "Новое устройство в аккаунте",
                vec![format!("К вашему аккаунту подключено устройство: {device}."), "Если это были не вы, проверьте список устройств и отзовите доступ незнакомого сеанса.".to_owned()],
                None,
                "Проверить устройства",
                ("account/devices", None),
                "Уведомление не содержит ключей или токенов доступа.",
            )
        }
    };
    let mut url = origin.join(path.0)?;
    if let Some((name, value)) = path.1 {
        url.query_pairs_mut().append_pair(name, value);
    }
    let paragraph_refs = paragraphs.iter().map(String::as_str).collect::<Vec<_>>();
    let origin_text = origin.as_str().trim_end_matches('/');
    let content = Content {
        lang: Lang::Ru,
        title,
        preheader: title,
        paragraphs: &paragraph_refs,
        code,
        link: Some(Link {
            button,
            url: url.as_str(),
        }),
        expiry,
        warning: "Не запрашивали это действие? Не передавайте код или ссылку другим людям. Если это письмо о новом устройстве, проверьте активные сеансы.",
        origin: origin_text,
    };
    let text = format!(
        "Vnox\n\n{title}\n\n{}\n\n{}\n{button}: {}\n\n{expiry}\n\nНе передавай код или ссылку другим людям.\n\n{origin_text}\n",
        paragraphs.join("\n\n"),
        code.map(|value| format!("Код: {value}\n"))
            .unwrap_or_default(),
        url.as_str(),
    );
    Ok(Email {
        subject: format!("Vnox — {title}"),
        text,
        html: layout::render(&content),
    })
}

/// Sign-in code message for the passwordless email flow. It carries no link and no
/// button: the code is typed into the page that requested it, never opened from a URL.
pub fn render_email_code(origin: &Url, code: &str, lang: Lang) -> Result<Email> {
    parse_origin(origin.as_str())?;
    if code.len() != 8 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("email code must contain exactly eight ASCII digits");
    }
    let (title, paragraph, expiry, warning, subject, label) = match lang {
        Lang::Ru => (
            "Код для входа в Vnox",
            "Введите этот код на странице входа. Он подойдёт только в том браузере, где вы запросили вход.",
            "Код действует 10 минут и срабатывает один раз.",
            "Не запрашивали вход? Просто проигнорируйте письмо и никому не сообщайте код.",
            "Vnox: код для входа",
            "Код",
        ),
        Lang::En => (
            "Your Vnox sign-in code",
            "Enter this code on the sign-in page. It only works in the browser where you asked to sign in.",
            "The code is valid for 10 minutes and works once.",
            "Did not ask to sign in? Ignore this message and never share the code.",
            "Vnox: sign-in code",
            "Code",
        ),
    };
    let origin_text = origin.as_str().trim_end_matches('/');
    let paragraphs = [paragraph];
    let html = layout::render(&Content {
        lang,
        title,
        preheader: title,
        paragraphs: &paragraphs,
        code: Some(code),
        link: None,
        expiry,
        warning,
        origin: origin_text,
    });
    let text = format!(
        "Vnox\n\n{title}\n\n{paragraph}\n\n{label}: {code}\n\n{expiry}\n\n{warning}\n\n{origin_text}\n"
    );
    Ok(Email {
        subject: subject.to_owned(),
        text,
        html,
    })
}

pub fn write_previews(directory: &std::path::Path, origin: &Url) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    for (name, kind) in [
        (
            "verify",
            Kind::Verify {
                token: "DUMMY_PREVIEW_NOT_A_REAL_TOKEN",
            },
        ),
        ("login", Kind::Login { code: "12345678" }),
        (
            "new-device",
            Kind::NewDevice {
                device: "Linux Desktop · пример",
            },
        ),
    ] {
        let email = render(origin, kind)?;
        std::fs::write(directory.join(format!("{name}.html")), email.html)?;
        std::fs::write(directory.join(format!("{name}.txt")), email.text)?;
    }
    Ok(())
}
