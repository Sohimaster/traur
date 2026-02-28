// Family: reputation
// Agenda: metadata-check
// Description: Flag packages with low reputation or missing metadata.

fn scan(pkg) {
    if pkg.metadata == () { return []; }
    
    let detections = [];
    let meta = pkg.metadata;
    
    // Vote signals
    if meta.num_votes == 0 {
        detections.push(#{score: 0.3, reason: "Package has zero votes"});
    } else if meta.num_votes < 5 {
        detections.push(#{score: 0.2, reason: "Package has very few votes (" + meta.num_votes + ")"});
    }
    
    // Popularity
    if meta.popularity == 0.0 {
        detections.push(#{score: 0.25, reason: "Popularity is 0.0 (no recent usage)"});
    }
    
    // Orphaned
    if meta.maintainer == "" {
        detections.push(#{score: 0.2, reason: "Package is orphaned (no maintainer)"});
    }
    
    // Missing URL
    if meta.url == "" {
        detections.push(#{score: 0.15, reason: "No upstream URL provided"});
    }
    
    // Missing license
    if meta.license.len() == 0 {
        detections.push(#{score: 0.1, reason: "No license specified"});
    }
    
    // Out of date
    if meta.out_of_date > 0 {
        detections.push(#{score: 0.05, reason: "Package is flagged as out of date"});
    }
    
    return detections;
}
