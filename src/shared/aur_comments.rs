use regex::Regex;
use std::sync::LazyLock;

use crate::shared::models::CommentEntry;

static COMMENT_CONTENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<div\s+id="comment-(\d+)-content"\s+class="article-content">([\s\S]*?)</div>"#).unwrap()
});

static COMMENT_DATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<h4\s+id="comment-(\d+)"\s+class="comment-header">[\s\S]*?<a[^>]*class="date"[^>]*>([^<]+)</a>"#).unwrap()
});

static HTML_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<[^>]+>").unwrap()
});

/// Fetch recent comments from an AUR package page.
/// Returns comment entries with parsed dates. Empty vec on error.
pub fn fetch_recent_comments(pkgbase: &str) -> Vec<CommentEntry> {
    let url = format!("https://aur.archlinux.org/packages/{pkgbase}");

    let resp = match reqwest::blocking::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let html = match resp.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    extract_comments(&html)
}

/// Extract comment entries (date + text) from AUR package page HTML.
///
/// Matches comment headers for dates and article-content divs for text,
/// pairing them by the numeric comment ID embedded in both elements' IDs.
fn extract_comments(html: &str) -> Vec<CommentEntry> {
    use std::collections::BTreeMap;

    // Collect dates by comment ID
    let mut dates: BTreeMap<u64, i64> = BTreeMap::new();
    for cap in COMMENT_DATE_RE.captures_iter(html) {
        let id: u64 = match cap[1].parse() {
            Ok(id) => id,
            Err(_) => continue,
        };
        let date_str = &cap[2];
        if let Some(ts) = parse_comment_date(date_str) {
            dates.insert(id, ts);
        }
    }

    // Collect comment texts by comment ID and pair with dates
    let mut entries: Vec<CommentEntry> = Vec::new();
    for cap in COMMENT_CONTENT_RE.captures_iter(html) {
        let id: u64 = match cap[1].parse() {
            Ok(id) => id,
            Err(_) => continue,
        };
        let raw = &cap[2];
        let text = HTML_TAG_RE.replace_all(raw, " ");
        let text = html_entities_decode(&text);
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.is_empty() {
            continue;
        }
        if let Some(&timestamp) = dates.get(&id) {
            entries.push(CommentEntry { timestamp, text });
        }
    }

    // Sort by timestamp descending (newest first) and limit to 10
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    entries.truncate(10);
    entries
}

/// Parse an AUR comment date like "2025-08-04 15:08 (UTC)" into a Unix timestamp.
fn parse_comment_date(date_str: &str) -> Option<i64> {
    // Strip " (UTC)" suffix
    let date_str = date_str.strip_suffix(" (UTC)")?;
    // Split "2025-08-04 15:08" into components
    let parts: Vec<&str> = date_str.split(&['-', ' ', ':'][..]).collect();
    if parts.len() != 5 {
        return None;
    }
    let year: i32 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;
    let hour: i64 = parts[3].parse().ok()?;
    let minute: i64 = parts[4].parse().ok()?;

    let days = days_from_civil(year, month, day)?;
    Some(days * 86400 + hour * 3600 + minute * 60)
}

/// Convert a Gregorian date to days since Unix epoch (1970-01-01).
/// Uses the algorithm from Howard Hinnant's date library.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if m == 0 || m > 12 || d == 0 || d > 31 {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;

    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 {
        y / 400
    } else {
        (y - 399) / 400
    };
    let yoe = (y - era * 400) as u32; // year of era [0, 399]
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1; // day of year [0, 365]
    let doe = (yoe as i64) * 365 + (yoe as i64) / 4 - (yoe as i64) / 100 + doy as i64;
    let epoch_days = era as i64 * 146097 + doe - 719468;
    Some(epoch_days)
}

/// Decode common HTML entities.
fn html_entities_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_comments_with_dates_from_html() {
        let html = r##"
        <div class="comments-header"><h3><span class="text">Latest Comments</span></h3></div>
        <h4 id="comment-1034958" class="comment-header">
            Larvey commented on <a href="#comment-1034958" class="date">2025-08-04 15:08 (UTC)</a>
        </h4>
        <div id="comment-1034958-content" class="article-content">
            <div><p>This package works great!</p></div>
        </div>
        <h4 id="comment-1032785" class="comment-header">
            Markil3 commented on <a href="#comment-1032785" class="date">2025-07-18 20:16 (UTC)</a>
        </h4>
        <div id="comment-1032785-content" class="article-content">
            <div><p>Found a <b>bug</b> in v2.</p></div>
        </div>
        "##;
        let comments = extract_comments(html);
        assert_eq!(comments.len(), 2);

        // Newest first
        assert_eq!(comments[0].text, "This package works great!");
        assert_eq!(comments[1].text, "Found a bug in v2.");

        // Verify timestamps are sensible (both are in 2025)
        assert!(comments[0].timestamp > 1_700_000_000, "timestamp should be in 2025");
        // Aug 4 should be after Jul 18
        assert!(comments[0].timestamp > comments[1].timestamp);
    }

    #[test]
    fn handles_empty_html() {
        assert!(extract_comments("").is_empty());
    }

    #[test]
    fn decodes_html_entities() {
        let html = r##"
        <h4 id="comment-1" class="comment-header">
            User commented on <a href="#comment-1" class="date">2025-06-01 12:00 (UTC)</a>
        </h4>
        <div id="comment-1-content" class="article-content">
            <div>&amp; &lt;test&gt;</div>
        </div>
        "##;
        let comments = extract_comments(html);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].text, "& <test>");
    }

    #[test]
    fn parse_comment_date_utc() {
        let ts = parse_comment_date("2025-08-04 15:08 (UTC)").unwrap();
        // 2025-08-04 15:08 UTC
        // Verify against computed value
        assert_eq!(ts, 1754320080);
    }

    #[test]
    fn parse_comment_date_winter() {
        let ts = parse_comment_date("2024-01-15 00:00 (UTC)").unwrap();
        // 2024-01-15 00:00 UTC = 1705276800
        assert_eq!(ts, 1705276800);
    }

    #[test]
    fn skips_comment_without_matching_date() {
        let html = r##"
        <h4 id="comment-1" class="comment-header">
            User commented on <a href="#comment-1" class="date">2025-06-01 12:00 (UTC)</a>
        </h4>
        <div id="comment-1-content" class="article-content"><div>text1</div></div>
        <div id="comment-999-content" class="article-content"><div>orphan text</div></div>
        "##;
        let comments = extract_comments(html);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].text, "text1");
    }

    #[test]
    fn date_parsing_roundtrip() {
        // Test a few dates to ensure days_from_civil is correct
        let cases = [
            ("2024-01-01 00:00 (UTC)", 1704067200),
            ("2024-12-31 23:59 (UTC)", 1735689540),
            ("2023-06-13 00:00 (UTC)", 1686614400),
        ];
        for (input, expected) in cases {
            let ts = parse_comment_date(input).unwrap();
            assert_eq!(ts, expected, "Failed for {input}: got {ts}, expected {expected}");
        }
    }
}
