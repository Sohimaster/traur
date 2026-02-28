// Family: reputation
// Agenda: maintainer-check
// Description: Risk scoring based on maintainer history and batch uploads.

fn scan(pkg) {
    if pkg.metadata == () { return []; }
    
    let now = now_timestamp();
    let detections = [];
    let maint_pkgs = pkg.maintainer_packages;
    
    // Single-package maintainer
    if maint_pkgs.len() == 1 {
        let age_days = (now - pkg.metadata.first_submitted) / 86400;
        if age_days < 30 {
            detections.push(#{score: 0.3, reason: "Maintainer has only 1 package, created " + age_days + " days ago"});
        } else {
            detections.push(#{score: 0.15, reason: "Maintainer has only 1 package"});
        }
    }
    
    // Batch upload detection: 3+ packages in last 48h
    let recent_cutoff = now - 48 * 3600;
    let recent_count = 0;
    for p in maint_pkgs {
        if p.first_submitted >= recent_cutoff {
            recent_count += 1;
        }
    }
    
    if recent_count >= 3 {
        detections.push(#{score: 0.45, reason: "Maintainer created " + recent_count + " packages in the last 48 hours"});
    }
    
    return detections;
}
