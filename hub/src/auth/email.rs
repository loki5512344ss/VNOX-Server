//! Passwordless email sign-in: address normalization, keyed MACs, one-time codes and
//! rate limits. Nothing in this module logs addresses, codes or network sources.

use std::{future::Future, pin::Pin, sync::Arc};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

use super::store::{hash, now};
use crate::mail::templates::Email;

/// Lifetime of a pending code. Also the cookie lifetime of the attempt binding.
pub const CODE_TTL: i64 = 600;
/// Verification tries per issued code, counted before the comparison.
pub const MAX_FAILURES: i64 = 5;
/// Pending attempts kept at once; protects the table from being filled by anonymous traffic.
const MAX_PENDING: i64 = 4096;
const CODE_DIGITS: usize = 8;

/// Delivery boundary. The production implementation is [`crate::mail::Mailer`]; tests
/// inject a recorder so no network traffic or real mail is ever produced.
pub trait CodeSender: Send + Sync {
    fn send<'a>(
        &'a self,
        recipient: &'a str,
        email: Email,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}

impl CodeSender for crate::mail::Mailer {
    fn send<'a>(
        &'a self,
        recipient: &'a str,
        email: Email,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(self.deliver(recipient, email))
    }
}

/// Send budgets. Every request that passes validation consumes budget, whether or not
/// delivery later succeeds, so the limits bound SMTP use and address harassment.
#[derive(Clone, Copy)]
pub struct EmailLimits {
    /// Minimum seconds between two codes for the same address.
    pub address_cooldown: i64,
    pub per_address_hour: i64,
    pub per_source_hour: i64,
    pub global_hour: i64,
}

impl Default for EmailLimits {
    fn default() -> Self {
        Self {
            address_cooldown: 60,
            per_address_hour: 5,
            per_source_hour: 10,
            global_hour: 300,
        }
    }
}

/// Enabled email sign-in. Holds the server MAC key; deliberately not Debug.
pub struct EmailAuth {
    key: [u8; 32],
    pub sender: Arc<dyn CodeSender>,
    pub limits: EmailLimits,
}

impl EmailAuth {
    pub fn new(key: [u8; 32], sender: Arc<dyn CodeSender>) -> Self {
        Self {
            key,
            sender,
            limits: EmailLimits::default(),
        }
    }

    /// HMAC-SHA256 under the server secret, domain separated and length prefixed so
    /// different field combinations can never produce the same input.
    pub fn mac(&self, domain: &str, parts: &[&str]) -> String {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.key)
            .expect("HMAC accepts any key length");
        for part in std::iter::once(domain).chain(parts.iter().copied()) {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        hex::encode(mac.finalize().into_bytes())
    }

    fn code_mac(&self, attempt_id: &str, email_mac: &str, code: &str) -> String {
        self.mac("vnox-email-code-v1", &[attempt_id, email_mac, code])
    }

    pub fn email_mac(&self, email: &str) -> String {
        self.mac("vnox-email-address-v1", &[email])
    }

    pub fn source_mac(&self, source: &str) -> String {
        self.mac("vnox-email-source-v1", &[source])
    }

    /// Atomically checks every send budget and records the send in one statement, so
    /// concurrent requests cannot overshoot a limit.
    pub async fn reserve_send(
        &self,
        pool: &SqlitePool,
        email_mac: &str,
        source_mac: &str,
    ) -> anyhow::Result<bool> {
        let t = now();
        let limits = self.limits;
        let result = sqlx::query(
            "INSERT INTO email_send_log(email_mac,source_mac,sent_at) SELECT ?,?,? WHERE \
             (SELECT COUNT(*) FROM email_send_log WHERE email_mac=? AND sent_at>?)=0 AND \
             (SELECT COUNT(*) FROM email_send_log WHERE email_mac=? AND sent_at>?)<? AND \
             (SELECT COUNT(*) FROM email_send_log WHERE source_mac=? AND sent_at>?)<? AND \
             (SELECT COUNT(*) FROM email_send_log WHERE sent_at>?)<?",
        )
        .bind(email_mac)
        .bind(source_mac)
        .bind(t)
        .bind(email_mac)
        .bind(t - limits.address_cooldown)
        .bind(email_mac)
        .bind(t - 3600)
        .bind(limits.per_address_hour)
        .bind(source_mac)
        .bind(t - 3600)
        .bind(limits.per_source_hour)
        .bind(t - 3600)
        .bind(limits.global_hour)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Stores a new pending attempt, replacing the one bound to the browser's previous
    /// cookie (a resend). Returns the generated code. Fails when capacity is reached.
    pub async fn create_attempt(
        &self,
        pool: &SqlitePool,
        email: &str,
        browser: &str,
        previous_browser: Option<&str>,
    ) -> anyhow::Result<(String, String)> {
        let mut transaction = pool.begin().await?;
        if let Some(previous) = previous_browser {
            sqlx::query("DELETE FROM email_attempts WHERE browser_hash=?")
                .bind(hash(previous))
                .execute(&mut *transaction)
                .await?;
        }
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_attempts")
            .fetch_one(&mut *transaction)
            .await?;
        anyhow::ensure!(pending < MAX_PENDING, "email login capacity reached");
        let attempt_id = super::store::token();
        let code = generate_code();
        let email_mac = self.email_mac(email);
        sqlx::query(
            "INSERT INTO email_attempts(attempt_id,browser_hash,email_mac,code_mac,expires_at) VALUES(?,?,?,?,?)",
        )
        .bind(&attempt_id)
        .bind(hash(browser))
        .bind(&email_mac)
        .bind(self.code_mac(&attempt_id, &email_mac, &code))
        .bind(now() + CODE_TTL)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok((attempt_id, code))
    }

    pub async fn discard_attempt(&self, pool: &SqlitePool, attempt_id: &str) {
        let _ = sqlx::query("DELETE FROM email_attempts WHERE attempt_id=?")
            .bind(attempt_id)
            .execute(pool)
            .await;
    }

    /// Checks a submitted code for the attempt bound to this browser.
    ///
    /// The try counter is incremented by the same atomic statement that selects the row, so
    /// parallel guesses cannot exceed [`MAX_FAILURES`]. A correct code is consumed by a
    /// `DELETE ... RETURNING`: exactly one caller can win it. Every failure mode (missing,
    /// expired, exhausted, wrong address, wrong code) is reported identically.
    pub async fn verify(
        &self,
        pool: &SqlitePool,
        email: &str,
        code: &str,
        browser: &str,
    ) -> anyhow::Result<bool> {
        let row: Option<(String, String, String, i64)> = sqlx::query_as(
            "UPDATE email_attempts SET failures=failures+1 WHERE browser_hash=? AND expires_at>? AND failures<? \
             RETURNING attempt_id,email_mac,code_mac,failures",
        )
        .bind(hash(browser))
        .bind(now())
        .bind(MAX_FAILURES)
        .fetch_optional(pool)
        .await?;
        let Some((attempt_id, stored_email, stored_code, failures)) = row else {
            return Ok(false);
        };
        let email_ok = self
            .email_mac(email)
            .as_bytes()
            .ct_eq(stored_email.as_bytes());
        let code_ok = self
            .code_mac(&attempt_id, &stored_email, code)
            .as_bytes()
            .ct_eq(stored_code.as_bytes());
        if !bool::from(email_ok & code_ok) {
            if failures >= MAX_FAILURES {
                self.discard_attempt(pool, &attempt_id).await;
            }
            return Ok(false);
        }
        let consumed: Option<String> = sqlx::query_scalar(
            "DELETE FROM email_attempts WHERE attempt_id=? AND expires_at>? RETURNING attempt_id",
        )
        .bind(&attempt_id)
        .bind(now())
        .fetch_optional(pool)
        .await?;
        Ok(consumed.is_some())
    }
}

/// Uniform eight-digit code from the OS-seeded CSPRNG, using rejection sampling to avoid
/// modulo bias.
pub fn generate_code() -> String {
    use rand::Rng;
    const SPAN: u64 = 10u64.pow(CODE_DIGITS as u32);
    const LIMIT: u64 = u64::MAX - u64::MAX % SPAN;
    loop {
        let mut bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < LIMIT {
            return format!("{:0width$}", value % SPAN, width = CODE_DIGITS);
        }
    }
}

/// True for exactly eight ASCII digits.
pub fn valid_code_shape(code: &str) -> bool {
    code.len() == CODE_DIGITS && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// Trims and lowercases an address and accepts a deliberately conservative subset of RFC
/// 5321: ASCII only, a dot-atom local part limited to `[a-z0-9._%+-]`, and a multi-label
/// hostname whose last label is alphabetic (no IP literals). `+tags` are kept, so different
/// tags are different identities. Unusual but legal addresses are rejected rather than
/// risk look-alike or parser-differential identities.
pub fn normalize_email(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.len() > 254 || !value.is_ascii() {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    if domain.contains('@') || local.is_empty() || local.len() > 64 {
        return None;
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
    {
        return None;
    }
    if domain.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2_construction() {
        // Sanity check of the primitive itself with the RFC 4231 test case 2 vector.
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn mac_fields_are_domain_separated_and_unambiguous() {
        struct Nop;
        impl CodeSender for Nop {
            fn send<'a>(
                &'a self,
                _: &'a str,
                _: Email,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
                Box::pin(async { Ok(()) })
            }
        }
        let auth = EmailAuth::new([7; 32], Arc::new(Nop));
        assert_ne!(auth.mac("a", &["bc"]), auth.mac("ab", &["c"]));
        assert_ne!(auth.mac("d", &["a", "bc"]), auth.mac("d", &["ab", "c"]));
        assert_ne!(auth.email_mac("x@y.zz"), auth.source_mac("x@y.zz"));
        let other = EmailAuth::new([8; 32], Arc::new(Nop));
        assert_ne!(auth.email_mac("x@y.zz"), other.email_mac("x@y.zz"));
    }

    #[test]
    fn codes_are_eight_digits_and_vary() {
        let codes: std::collections::HashSet<String> = (0..64).map(|_| generate_code()).collect();
        assert!(codes.len() > 60);
        assert!(codes.iter().all(|code| valid_code_shape(code)));
    }

    #[test]
    fn normalization_accepts_and_rejects_expected_shapes() {
        assert_eq!(
            normalize_email("  Person.Name+Tag@Example.COM \n").as_deref(),
            Some("person.name+tag@example.com")
        );
        for bad in [
            "",
            "plain",
            "a@b",
            "a@@b.cc",
            "a@b@c.cc",
            "@b.cc",
            "a b@c.cc",
            ".a@b.cc",
            "a.@b.cc",
            "a..b@c.cc",
            "\"a\"@b.cc",
            "a@b.c",
            "a@b.123",
            "a@[127.0.0.1]",
            "a@-b.cc",
            "a@b-.cc",
            "a@b..cc",
            "а@b.cc",
            "a@b.cc\r\nBcc: x@y.cc",
            "a<script>@b.cc",
        ] {
            assert!(normalize_email(bad).is_none(), "{bad:?}");
        }
        assert!(normalize_email(&format!("{}@b.cc", "a".repeat(65))).is_none());
        assert!(normalize_email(&format!("a@{}.cc", "b".repeat(64))).is_none());
        assert!(normalize_email(&format!("a@{}.cc", "b.".repeat(130))).is_none());
    }
}
