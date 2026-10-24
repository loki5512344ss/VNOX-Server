/// Escape all dynamic HTML, including attribute values.
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Language of the fixed layout chrome (tagline, footer, hints).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    /// Parses a client supplied language tag; anything unknown falls back to Russian.
    pub fn from_tag(tag: Option<&str>) -> Self {
        match tag {
            Some("en") => Self::En,
            _ => Self::Ru,
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
        }
    }
}

/// Optional call-to-action. Code messages deliberately carry none.
pub struct Link<'a> {
    pub button: &'a str,
    pub url: &'a str,
}

pub struct Content<'a> {
    pub lang: Lang,
    pub title: &'a str,
    pub preheader: &'a str,
    pub paragraphs: &'a [&'a str],
    pub code: Option<&'a str>,
    pub link: Option<Link<'a>>,
    pub expiry: &'a str,
    pub warning: &'a str,
    pub origin: &'a str,
}

/// Table-based inline HTML with a solid-color fallback for gradient support.
pub fn render(content: &Content<'_>) -> String {
    let paragraphs = content
        .paragraphs
        .iter()
        .map(|value| {
            format!(
                "<p style=\"margin:0 0 16px;font-size:16px;line-height:26px;color:#eae6df\">{}</p>",
                escape(value)
            )
        })
        .collect::<String>();
    let code = content.code.map(|value| format!("<p style=\"margin:22px 0;padding:18px;background:#111112;border:1px solid #494238;border-radius:10px;font-family:Consolas,monospace;font-size:30px;font-weight:700;letter-spacing:6px;text-align:center;color:#f0d7ae\">{}</p>", escape(value))).unwrap_or_default();
    let title = escape(content.title);
    let (tagline, automatic) = match content.lang {
        Lang::Ru => (
            "Личное пространство для общения",
            "Автоматическое письмо Vnox. Отвечать на него не нужно.",
        ),
        Lang::En => (
            "A personal space to talk",
            "Automatic message from Vnox. No need to reply.",
        ),
    };
    let link = content
        .link
        .as_ref()
        .map(|link| {
            let url = escape(link.url);
            let button = escape(link.button);
            let hint = match content.lang {
                Lang::Ru => "Если кнопка не открывается, скопируй ссылку:",
                Lang::En => "If the button does not open, copy the link:",
            };
            format!(
                r##"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:23px 0 17px"><tr><td bgcolor="#d5b58a" style="border-radius:9px"><a href="{url}" style="display:inline-block;padding:14px 26px;color:#231d16;text-decoration:none;font-size:15px;font-weight:700;border-radius:9px">{button}</a></td></tr></table>
<p style="margin:0 0 9px;font-size:12px;color:#aca49a">{hint}</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td bgcolor="#171718" style="padding:13px;border:1px solid #3c3732;border-radius:9px;word-break:break-all;font-size:12px;line-height:20px"><a href="{url}" style="color:#d8bd98;text-decoration:none">{url}</a></td></tr></table>"##
            )
        })
        .unwrap_or_default();
    let origin = escape(content.origin);
    format!(
        r##"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#101011" bgcolor="#101011">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#101011"><tr><td align="center" style="padding:32px 12px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="#1c1c1e" style="width:100%;max-width:600px;border:1px solid #383634;border-radius:18px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif">
<tr><td bgcolor="#38312a" style="background:#38312a;background-image:linear-gradient(125deg,#514033 0%,#39312c 55%,#242426 100%);padding:30px 32px 32px">
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="42" height="42" align="center" bgcolor="#151516" style="border-radius:11px;color:#e8d5b8;font-size:19px;font-weight:800"><img src="{origin}/assets/vnox-mark-email.png" width="42" height="42" alt="V" style="display:block;border:0;border-radius:11px"></td><td style="padding-left:12px;color:#f6f0e7;font-size:23px;font-weight:700">Vnox</td></tr></table>
<p style="margin:25px 0 10px;color:#d1b998;font-size:12px">{tagline}</p>
<h1 style="margin:0;color:#fff9ef;font-size:28px;line-height:35px;font-weight:700">{title}</h1>
</td></tr><tr><td style="padding:32px 32px 12px">{paragraphs}{code}{link}
<p style="margin:0 0 24px;font-size:13px;line-height:21px;color:#aca49a">{expiry}</p>
<p style="margin:26px 0 18px;font-size:13px;line-height:21px;color:#aca49a">{warning}</p>
</td></tr><tr><td bgcolor="#171718" style="border-top:1px solid #383634;padding:21px 32px;color:#9e978d;font-size:12px;line-height:20px">{automatic}<br><a href="{origin}" style="color:#d8bd98;text-decoration:none">{origin}</a></td></tr></table></td></tr></table></body></html>"##,
        lang = content.lang.tag(),
        preheader = escape(content.preheader),
        expiry = escape(content.expiry),
        warning = escape(content.warning),
    )
}
