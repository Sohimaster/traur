// Family: gtfobins
// Agenda: pre-transaction
// Description: Abuse of legitimate binaries catalogued on GTFOBins.

fn scan(pkg) {
    if pkg.pkgbuild_content == "" { return []; }
    return match_patterns(pkg.pkgbuild_content, "gtfobins_analysis");
}
