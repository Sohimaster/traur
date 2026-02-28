// Family: reputation
// Agenda: git-check
// Description: Detects suspicious changes between package versions.

fn scan(pkg) {
    if pkg.prior_pkgbuild_content == "" { return []; }
    
    let detections = [];
    let new_content = pkg.pkgbuild_content;
    let old_content = pkg.prior_pkgbuild_content;
    
    // Checksum removed or changed to SKIP
    let old_has_ck = test_regex(old_content, `(?m)^(md5|sha\d+|b2)sums`);
    let new_has_ck = test_regex(new_content, `(?m)^(md5|sha\d+|b2)sums`);
    
    if old_has_ck && !new_has_ck {
        detections.push(#{score: 0.35, reason: "Checksum array removed in latest update"});
    }
    
    return detections;
}
