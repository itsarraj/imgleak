//! Content and filename detectors for secrets baked into an image
//! layer. Pattern shapes are written independently, referencing only
//! publicly documented categories (AWS access keys, PEM private key
//! headers, generic password/API-key assignments) - the same scope
//! this monorepo's `leakscan` uses for git-diff scanning, adapted here
//! for scanning a file's full content rather than a single diff line.

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    AwsAccessKey,
    PrivateKey,
    GenericPassword,
    GenericApiKey,
    SuspiciousFilename,
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            SecretKind::AwsAccessKey => "AWS Access Key ID",
            SecretKind::PrivateKey => "Private Key",
            SecretKind::GenericPassword => "Hardcoded Password",
            SecretKind::GenericApiKey => "Generic API Key",
            SecretKind::SuspiciousFilename => "Sensitive Filename",
        }
    }

    /// Filename-based findings are a weaker signal than a value that
    /// actually matched a content pattern (the filename could be a
    /// harmless empty placeholder), so callers treat this kind as a
    /// lower severity.
    pub fn is_content_match(&self) -> bool {
        !matches!(self, SecretKind::SuspiciousFilename)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMatch {
    pub kind: SecretKind,
    pub detail: String,
}

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("static pattern is valid regex"))
        }
    };
}

static_regex!(aws_key_re, r"\bAKIA[0-9A-Z]{16}\b");
static_regex!(
    private_key_re,
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
);
// Note: Rust's `regex` crate is a finite-automaton engine with no
// backreference support, so a strict "opening quote must match closing
// quote" pattern (`(['"])...\1`) isn't expressible here. Both patterns
// below instead allow an optional quote on either side independently -
// slightly looser (a mismatched-quote line isn't real syntax for
// anything this scans anyway, so the only practical effect is not
// rejecting one) rather than requiring symmetry.
// Deliberately no leading `\b` before the keyword: `.env`-style files
// routinely prefix these with an underscore-joined scope
// (`DB_PASSWORD=`, `STRIPE_API_KEY=`), and `_` counts as a word
// character in regex - a leading `\b` would fail to match right at
// the point this tool most needs it to. The trailing `\b` plus the
// required `[:=]` right after keeps it from firing on an unrelated
// word that merely contains "password" as a substring with no
// assignment following it.
static_regex!(
    password_re,
    r#"(?i)(?:password|passwd|pwd)\b\s*[:=]\s*['"]?([^\s'"]{4,})['"]?"#
);
static_regex!(
    generic_api_key_re,
    r#"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"]?([A-Za-z0-9+/_=\-]{12,})['"]?"#
);

const PLACEHOLDER_VALUES: &[&str] = &[
    "changeme",
    "change_me",
    "your_password_here",
    "your_api_key_here",
    "replaceme",
    "placeholder",
    "example",
    "todo",
    "fixme",
    "password",
    "secret",
    "<password>",
    "<api_key>",
];

fn is_placeholder(value: &str) -> bool {
    PLACEHOLDER_VALUES.contains(&value.to_lowercase().as_str())
}

/// Scans one file's full text content for known secret shapes. A file
/// can trigger multiple distinct findings (e.g. a `.env`-style file
/// with both an AWS key and a password on different lines).
pub fn scan_content(content: &str) -> Vec<ContentMatch> {
    let mut matches = Vec::new();

    for m in aws_key_re().find_iter(content) {
        matches.push(ContentMatch {
            kind: SecretKind::AwsAccessKey,
            detail: m.as_str().to_string(),
        });
    }
    for m in private_key_re().find_iter(content) {
        matches.push(ContentMatch {
            kind: SecretKind::PrivateKey,
            detail: m.as_str().to_string(),
        });
    }
    for caps in password_re().captures_iter(content) {
        let value = caps.get(1).expect("group 1 always present").as_str();
        if is_placeholder(value) {
            continue;
        }
        matches.push(ContentMatch {
            kind: SecretKind::GenericPassword,
            detail: format!("password = {value}"),
        });
    }
    for caps in generic_api_key_re().captures_iter(content) {
        let value = caps.get(1).expect("group 1 always present").as_str();
        if is_placeholder(value) {
            continue;
        }
        matches.push(ContentMatch {
            kind: SecretKind::GenericApiKey,
            detail: format!("key = {value}"),
        });
    }

    matches
}

/// Well-known sensitive filenames/paths worth flagging regardless of
/// content — a binary-encoded private key or a file this tool's size
/// cap skipped would otherwise slip past `scan_content` entirely.
const SUSPICIOUS_BASENAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".env",
    ".netrc",
    ".npmrc",
    ".git-credentials",
    ".pgpass",
    "credentials",
    "shadow",
];
const SUSPICIOUS_SUFFIXES: &[&str] = &[".pem", ".key", ".pfx", ".p12"];

pub fn suspicious_filename_reason(path: &str) -> Option<String> {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if SUSPICIOUS_BASENAMES.contains(&basename) {
        return Some(format!(
            "filename '{basename}' is a well-known credentials file"
        ));
    }
    if path.ends_with("/.aws/credentials") || path == ".aws/credentials" {
        return Some("AWS CLI credentials file".to_string());
    }
    if path.ends_with("/.docker/config.json") || path == ".docker/config.json" {
        return Some("Docker registry auth config (base64 credentials)".to_string());
    }
    for suffix in SUSPICIOUS_SUFFIXES {
        if basename.ends_with(suffix) {
            return Some(format!(
                "filename extension '{suffix}' commonly holds key material"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(content: &str) -> Vec<SecretKind> {
        scan_content(content).into_iter().map(|m| m.kind).collect()
    }

    #[test]
    fn detects_an_aws_access_key() {
        let content = r#"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"#;
        assert_eq!(kinds(content), vec![SecretKind::AwsAccessKey]);
    }

    #[test]
    fn detects_a_private_key_header() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----";
        assert_eq!(kinds(content), vec![SecretKind::PrivateKey]);
    }

    #[test]
    fn detects_a_hardcoded_password_in_env_style_content() {
        let content = "DB_PASSWORD=hunter2secret";
        assert_eq!(kinds(content), vec![SecretKind::GenericPassword]);
    }

    #[test]
    fn placeholder_password_is_not_flagged() {
        assert!(kinds("PASSWORD=changeme").is_empty());
    }

    #[test]
    fn detects_a_generic_api_key_assignment() {
        let content = "API_KEY=abcdEFGH12345678ijkl";
        assert_eq!(kinds(content), vec![SecretKind::GenericApiKey]);
    }

    #[test]
    fn ordinary_text_is_not_flagged() {
        let content = "This is a README describing how the service starts up.";
        assert!(kinds(content).is_empty());
    }

    #[test]
    fn multiple_findings_in_one_file_are_all_reported() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=realvalue123";
        let hits = kinds(content);
        assert_eq!(hits.len(), 2);
        assert!(hits.contains(&SecretKind::AwsAccessKey));
        assert!(hits.contains(&SecretKind::GenericPassword));
    }

    #[test]
    fn suspicious_filename_flags_ssh_private_keys() {
        assert!(suspicious_filename_reason("home/user/.ssh/id_rsa").is_some());
        assert!(suspicious_filename_reason("id_ed25519").is_some());
    }

    #[test]
    fn suspicious_filename_flags_dotenv_and_credential_files() {
        assert!(suspicious_filename_reason("app/.env").is_some());
        assert!(suspicious_filename_reason(".npmrc").is_some());
        assert!(suspicious_filename_reason("root/.aws/credentials").is_some());
    }

    #[test]
    fn suspicious_filename_flags_key_and_pem_extensions() {
        assert!(suspicious_filename_reason("certs/server.pem").is_some());
        assert!(suspicious_filename_reason("certs/server.key").is_some());
    }

    #[test]
    fn ordinary_filenames_are_not_flagged() {
        assert!(suspicious_filename_reason("app/main.py").is_none());
        assert!(suspicious_filename_reason("README.md").is_none());
    }

    #[test]
    fn is_content_match_distinguishes_filename_only_findings() {
        assert!(SecretKind::AwsAccessKey.is_content_match());
        assert!(!SecretKind::SuspiciousFilename.is_content_match());
    }
}
