use anyhow::{Result, bail};
use std::net::{IpAddr, SocketAddr};
use url::Url;

pub fn endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || value.len() > 2048
    {
        bail!("webhook target must be an HTTPS URL without credentials, query or fragment")
    }
    if let Ok(ip) = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        && !public_ip(ip)
    {
        bail!("webhook target address is not public")
    }
    Ok(url)
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(v4));
            }
            let s = ip.segments();
            (0x2000..=0x3fff).contains(&s[0])
                && s[0] != 0x2002
                && s[0] != 0x3ffe
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}

/// Resolve every attempt and pin the same validated addresses into the HTTP client.
/// Mixed public/private answers are rejected rather than trusting resolver ordering.
pub async fn resolve(url: &Url) -> Result<Vec<SocketAddr>> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing target host"))?
        .trim_matches(['[', ']']);
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))),
    )
    .await??
    .collect::<Vec<_>>();
    if addresses.len() > 32 || addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip()))
    {
        bail!("webhook target DNS contains a non-public address")
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_internal_special_and_mapped_addresses() {
        for value in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "3fff::1",
        ] {
            assert!(!public_ip(value.parse().unwrap()), "{value}");
        }
        for value in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(value.parse().unwrap()))
        }
    }
    #[test]
    fn urls_require_clean_https_origin_and_path() {
        for value in [
            "http://example.org",
            "https://user:pass@example.org",
            "https://example.org/?token=x",
            "https://127.0.0.1",
            "file:///etc/passwd",
        ] {
            assert!(endpoint(value).is_err());
        }
        assert!(endpoint("https://example.org/events").is_ok());
    }
}
