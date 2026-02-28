// Family: reputation
// Agenda: metadata-check
// Description: Security warnings in AUR package comments.

fn scan(pkg) {
    let keywords = ["malware", "backdoor", "trojan", "keylogger", "cryptominer", "compromised", "malicious", "unsafe", "dangerous"];
    
    for comment in pkg.aur_comments {
        let lower = comment.to_lowercase();
        for kw in keywords {
            if lower.contains(kw) {
                return [#{score: 0.4, reason: "AUR comment mentions security concern (keyword: " + kw + ")"}];
            }
        }
    }
    
    return [];
}
