// Family: network
// Agenda: pre-transaction
// Description: Intelligent analysis of source URLs for suspicious patterns and mismatches.

fn scan(pkg) {
    if pkg.pkgbuild_content == "" { return []; }
    
    let content = pkg.pkgbuild_content;
    let source_content = find_regex(content, `(?ms)^source=\((.*?)\)`);
    if source_content == "" { return []; }
    
    let detections = [];
    
    // Extract upstream URL for comparison
    let upstream_url = if pkg.metadata != () { pkg.metadata.url } else { "" };
    let upstream_domain = extract_domain(upstream_url);
    
    // Check for suspicious URL patterns
    let has_shortener = test_regex(source_content, `(bit\.ly|tinyurl\.com|t\.co|is\.gd)`);
    let has_raw_ip = test_regex(source_content, `https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`);
    let has_discord_webhook = test_regex(source_content, `discord(app)?\.com/api/webhooks`);
    let has_suspicious_domain = test_regex(source_content, `(malicious|evil|exploit|payload|backdoor)`);
    
    // For -bin packages, check if source domain matches upstream
    let is_bin_pkg = pkg.name.contains("-bin");
    let source_domains = [];
    // Simple extraction of domains from URLs in source array
    let domain_pattern = `(?:https?://)?([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,}))`;
    // This is simplified - real implementation would extract all
    
    // YARA-style verdicts based on pattern combinations
    
    // Highest risk: webhook exfiltration channel
    if has_discord_webhook {
        detections.push(#{id: "R-URL-EXFIL-DISCORD", score: 0.95, reason: "Source uses Discord webhook (data exfiltration channel)"});
        return detections;
    }
    
    // Very high risk: raw IP + mimic suspicious pattern
    if has_raw_ip && has_suspicious_domain {
        detections.push(#{id: "R-URL-IP-SUSPICIOUS", score: 0.90, reason: "Raw IP address in source with suspicious naming"});
        return detections;
    }
    
    // High risk: URL shortener (hiding real destination)
    if has_shortener {
        detections.push(#{id: "R-URL-SHORTENER", score: 0.75, reason: "Source uses URL shortener (hiding true destination)"});
    }
    
    // Medium-high risk: raw IP
    if has_raw_ip {
        detections.push(#{id: "R-URL-RAW-IP", score: 0.65, reason: "Source uses raw IP instead of domain"});
    }
    
    // Medium risk: -bin package with mismatched source domain
    if is_bin_pkg && upstream_domain != "" && !source_content.contains(upstream_domain) {
        detections.push(#{id: "R-URL-BIN-MISMATCH", score: 0.60, reason: "-bin package sources differ from upstream domain"});
    }
    
    return detections;
}

