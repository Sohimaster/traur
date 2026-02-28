// Family: reputation
// Agenda: maintainer-check
// Description: Detects adopted packages with new git authors (orphan takeover).

fn scan(pkg) {
    if pkg.metadata == () { return []; }
    let meta = pkg.metadata;
    if meta.submitter == "" || meta.maintainer == "" { return []; }
    if meta.submitter == meta.maintainer { return []; }

    let detections = [];
    detections.push(#{score: 0.15, reason: "Package maintainer (" + meta.maintainer + ") differs from original submitter (" + meta.submitter + ")"});

    // Orphan takeover pattern
    let now = now_timestamp();
    let is_established = (now - meta.first_submitted) > (90 * 86400);

    if pkg.git_log.len() >= 2 && is_established {
        let latest_author = pkg.git_log[0].author;
        let is_new_author = true;
        for i in 1..pkg.git_log.len() {
            if pkg.git_log[i].author == latest_author {
                is_new_author = false;
                break;
            }
        }

        if is_new_author {
            detections.push(#{score: 0.5, reason: "Adopted package with new git author (" + latest_author + ") — orphan takeover pattern"});
        }
    }

    return detections;
}
