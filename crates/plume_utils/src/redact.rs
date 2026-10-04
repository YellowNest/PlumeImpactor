use std::sync::LazyLock;

use regex::Regex;

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("valid email regex")
});

/// Mask a single email address, keeping the domain in cleartext
/// and redacting the local part.
///
/// - If the local part is longer than 3 chars, keep the first 3 chars
///   and pad the rest with `*`,
///   e.g. `test@example.com` -> `tes*@example.com`
/// - If the local part is 3 chars or shorter, output `***@domain`,
///   e.g. `ab@dr.com` -> `***@dr.com`, to avoid leaking short emails.
pub fn mask_email(email: &str) -> String {
    let Some(at_pos) = email.find('@') else {
        return email.to_string();
    };
    if at_pos == 0 {
        return email.to_string();
    }
    let domain = &email[at_pos..];
    if at_pos <= 3 {
        return format!("***{domain}");
    }
    let keep_chars = 3;
    let prefix = &email[..keep_chars];
    let stars = "*".repeat(at_pos - keep_chars);
    format!("{prefix}{stars}{domain}")
}

/// Scan arbitrary text and replace every email address with its masked form.
/// Used to sanitize log output from third-party crates (e.g. apple-codesign
/// logging a certificate CN like `iPhone Developer: xxx@dr.com (TEAMID)`).
pub fn sanitize_emails_in_text(text: &str) -> String {
    EMAIL_RE
        .replace_all(text, |caps: &regex::Captures| mask_email(&caps[0]))
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_email_long() {
        assert_eq!(mask_email("test@example.com"), "tes*@example.com");
        assert_eq!(mask_email("longname@dr.com"), "lon*****@dr.com");
    }

    #[test]
    fn test_mask_email_short() {
        // Short local parts must not leak in cleartext
        assert_eq!(mask_email("ab@dr.com"), "***@dr.com");
        assert_eq!(mask_email("abc@dr.com"), "***@dr.com");
        assert_eq!(mask_email("a@dr.com"), "***@dr.com");
    }

    #[test]
    fn test_mask_email_invalid() {
        assert_eq!(mask_email("not-an-email"), "not-an-email");
        assert_eq!(mask_email("@dr.com"), "@dr.com");
    }

    #[test]
    fn test_sanitize_certificate_cn() {
        let input = "creating cryptographic signature with certificate iPhone Developer: testuser@dr.com (WFKD4XV283)";
        let out = sanitize_emails_in_text(input);
        assert!(!out.contains("testuser@dr.com"), "raw email leaked: {out}");
        assert!(out.contains("tes*****@dr.com"), "unexpected: {out}");
        assert!(
            out.contains("(WFKD4XV283)"),
            "team id should be kept: {out}"
        );
    }

    #[test]
    fn test_sanitize_multiple_and_no_email() {
        let input = "no email here";
        assert_eq!(sanitize_emails_in_text(input), input);

        let input = "a@b.co and longname@dr.com done";
        let out = sanitize_emails_in_text(input);
        assert!(!out.contains("longname@dr.com"));
        assert!(out.contains("lon*****@dr.com"));
    }
}
