// Family: reputation
// Agenda: pre-transaction
// Description: Domain and GitHub organization verification for -bin packages.

fn scan(pkg) {
    if !pkg.name.contains("-bin") { return []; }
    if pkg.metadata == () || pkg.metadata.url == "" { return []; }
    
    let upstream_url = pkg.metadata.url;
    let upstream_org = extract_github_org(upstream_url);
    
    let source_content = find_regex(pkg.pkgbuild_content, `(?ms)^source=(.*?)\)`);
    if source_content == "" { return []; }
    
    let detections = [];
    
    if source_content.contains("github.com") && upstream_org != "" {
        let src_org = extract_github_org(source_content);
        if src_org != "" && src_org != upstream_org {
            detections.push(#{score: 0.5, reason: "-bin package upstream is github.com/" + upstream_org + " but source downloads from different org"});
        }
    }
    
    return detections;
}
