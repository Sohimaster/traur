// Family: reputation
// Agenda: git-check
// Description: Anomalies in git commit history and recent diffs.

fn scan(pkg) {
    if pkg.git_log.len() == 0 { return []; }
    
    let detections = [];
    let now = now_timestamp();

    // T-SINGLE-COMMIT
    if pkg.git_log.len() == 1 {
        detections.push(#{score: 0.2, reason: "Git history has only 1 commit"});
    }

    // T-NEW-PACKAGE
    let created = if pkg.metadata != () { pkg.metadata.first_submitted } else { pkg.git_log[pkg.git_log.len()-1].timestamp };
    let age_days = (now - created) / 86400;
    if age_days < 7 && age_days >= 0 {
        detections.push(#{score: 0.25, reason: "Package is very new (" + age_days + " days old)"});
    }

    // T-MALICIOUS-DIFF
    let net_pattern = `(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)`;
    if pkg.git_log[0].diff != "" {
        if test_regex(pkg.git_log[0].diff, `\+.*` + net_pattern) {
            let has_prior_net = test_regex(pkg.prior_pkgbuild_content, net_pattern);
            if !has_prior_net {
                detections.push(#{score: 0.55, reason: "Latest commit introduces network code not present in prior history"});
            }
        }
    }

    // T-AUTHOR-CHANGE
    if pkg.git_log.len() >= 2 {
        let authors = [];
        for commit in pkg.git_log {
            let found = false;
            for a in authors { if a == commit.author { found = true; break; } }
            if !found { authors.push(commit.author); }
        }
        if authors.len() > 1 {
            detections.push(#{score: 0.25, reason: "Git history shows multiple different authors"});
        }
    }

    return detections;
}
