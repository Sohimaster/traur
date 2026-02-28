// Family: reputation
// Agenda: metadata-check
// Description: Scoring based on upstream GitHub repository popularity.

fn scan(pkg) {
    if pkg.github_not_found {
        return [#{score: 0.25, reason: "Upstream URL points to GitHub but repo does not exist"}];
    }
    
    if pkg.github_stars >= 0 {
        if pkg.github_stars == 0 {
            return [#{score: 0.2, reason: "Upstream GitHub repo has 0 stars"}];
        } else if pkg.github_stars < 10 {
            return [#{score: 0.1, reason: "Upstream GitHub repo has very few stars (" + pkg.github_stars + ")"}];
        }
    }
    
    return [];
}
