//! Formatting primitives shared by every view.
//!
//! The only subtle code here is [`escape`]. Everything interpolated into a page
//! goes through it, because the data being displayed is *attacker-influenced by
//! definition* — a command line, an image path, a hostname. A console that
//! renders telemetry without escaping is a stored-XSS delivery mechanism.
//!
//! [`decode`] and [`encode`] exist because the console has no JavaScript, so
//! every filter is a link. A link is a URL, and a URL is a place where a
//! technique id or a hostname has to survive a round trip intact.

use chrono::{DateTime, Utc};
use model::Severity;

/// Escape text for interpolation into HTML.
///
/// Covers the five characters that matter in both element and attribute
/// context: `&` (which must be first, or it would double-escape the others),
/// the two angle brackets, and both quote styles.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Group digits, so a seven-figure count is readable at a glance.
///
/// Worth ten lines because every number on the page is an order-of-magnitude
/// claim: `2600000` and `260000` differ by one character and by everything.
pub fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Trim an RFC 3339 timestamp to something readable in a table.
pub fn stamp(rfc3339: &str) -> String {
    rfc3339.get(..19).unwrap_or(rfc3339).replace('T', " ")
}

/// How long ago, in the compact form a table wants.
///
/// Complements the absolute timestamp rather than replacing it: "2h" answers
/// "is this still happening" at a glance, which `2026-09-18 08:41:07` does not.
///
/// Saturates at zero rather than going negative, because a clock that has moved
/// backwards should read as "now" and not as a timestamp from the future.
pub fn age(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let seconds = (now - at).num_seconds().max(0);
    match seconds {
        0..=1 => "now".to_string(),
        2..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m", seconds / 60),
        3_600..=86_399 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// A fixed class name for a severity.
///
/// A match on the enum, never the value's own text: severity reaches the page
/// typed, and a class built from a string is the other classic XSS route.
pub fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Parse a severity name, accepting the forms that appear in URLs.
pub fn severity_from_str(value: &str) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

/// Percent-decode a URL component.
///
/// Hand-rolled rather than pulled in, because the alternative is a dependency
/// for twenty lines — and because the failure mode matters: a malformed escape
/// is passed through as written rather than rejected, so one bad character in a
/// URL cannot make the console return nothing at all.
pub fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
            {
                (Some(high), Some(low)) => {
                    out.push((high << 4) | low);
                    i += 3;
                }
                // A truncated or non-hex escape is literal text, not an error:
                // dropping it would silently change the filter.
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a query-string component.
///
/// Only what has to be encoded is, which keeps technique ids and hostnames
/// legible in the address bar and in a screenshot.
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push(hex_char(other >> 4));
                out.push(hex_char(other & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + nibble - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn escaping_covers_every_dangerous_character() {
        assert_eq!(escape(""), "");
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("<script>"), "&lt;script&gt;");
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape("it's"), "it&#39;s");
        // Ampersand first, so entities are not double-escaped.
        assert_eq!(escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn thousands_groups_from_the_right() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(20_000), "20,000");
        assert_eq!(thousands(999_999), "999,999");
        assert_eq!(thousands(2_600_000), "2,600,000");
        assert_eq!(thousands(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn timestamps_are_trimmed_rather_than_left_raw() {
        assert_eq!(stamp("2026-01-02T03:04:05.678Z"), "2026-01-02 03:04:05");
        assert_eq!(stamp("short"), "short");
    }

    #[test]
    fn age_is_compact_and_saturates_at_now() {
        let now = Utc::now();
        assert_eq!(age(now, now), "now");
        assert_eq!(age(now, now - Duration::seconds(45)), "45s");
        assert_eq!(age(now, now - Duration::minutes(5)), "5m");
        assert_eq!(age(now, now - Duration::hours(3)), "3h");
        assert_eq!(age(now, now - Duration::days(2)), "2d");
        assert_eq!(age(now, now + Duration::minutes(5)), "now");
    }

    #[test]
    fn severities_round_trip_through_a_url() {
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let text = severity_class(severity);
            assert_eq!(severity_from_str(text), Some(severity));
        }
        assert_eq!(severity_from_str("CRITICAL"), Some(Severity::Critical));
        assert_eq!(severity_from_str("bogus"), None);
    }

    #[test]
    fn decoding_handles_the_escapes_a_filter_can_produce() {
        assert_eq!(decode("critical"), "critical");
        assert_eq!(decode("T1059.001"), "T1059.001");
        assert_eq!(decode("a+b"), "a b");
        assert_eq!(decode("%2Ftmp%2Fsvchost.exe"), "/tmp/svchost.exe");
        assert_eq!(decode("%2f%2F"), "//", "hex digits are case-insensitive");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("%2"), "%2");
    }

    #[test]
    fn encoding_leaves_the_legible_things_legible() {
        assert_eq!(encode("T1059.001"), "T1059.001");
        assert_eq!(encode("9cb0576466660906"), "9cb0576466660906");
        assert_eq!(encode("a b"), "a+b");
        assert_eq!(encode("a/b"), "a%2Fb");
        assert_eq!(encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(encode("<script>"), "%3Cscript%3E");
    }

    #[test]
    fn encoding_then_decoding_is_the_identity() {
        for value in [
            "T1059.001",
            "C:\\Users\\a b\\svchost.exe",
            "a&b=c",
            "100%",
            "=?+",
            "\u{e9}\u{4e2d}\u{6587}",
        ] {
            assert_eq!(decode(&encode(value)), value, "round trip of {value:?}");
        }
    }
}
