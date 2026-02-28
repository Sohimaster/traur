use serde::Deserialize;
use std::fs;
use traur::coordinator::scan_pkgbuild;

#[derive(Debug, Deserialize)]
struct TestConfig {
    tests: Vec<RuleTest>,
}

#[derive(Debug, Deserialize)]
struct RuleTest {
    name: String,
    pkgname: String,
    pkgbuild: String,
    expected_detections: Vec<String>,
    expected_verdict: String,
}

#[test]
fn run_rule_tests() {
    let config_dir = "tests/configs";
    let entries = fs::read_dir(config_dir).expect("Failed to read tests/configs");

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "toml") {
            let content = fs::read_to_string(&path).expect("Failed to read test config");
            let config: TestConfig = toml::from_str(&content).expect("Failed to parse test TOML");

            for test in config.tests {
                println!("Running test: {}", test.name);
                let result = scan_pkgbuild(&test.pkgname, &test.pkgbuild);
                
                let actual_ids: Vec<String> = result.detections.iter().map(|d| d.rule_id.clone()).collect();
                
                for expected_id in &test.expected_detections {
                    assert!(actual_ids.contains(expected_id), 
                        "Test '{}' failed: expected detection {} not found. Actual detections: {:?}", 
                        test.name, expected_id, actual_ids);
                }
                
                let actual_verdict = format!("{:?}", result.verdict);
                assert_eq!(actual_verdict, test.expected_verdict, 
                    "Test '{}' failed: verdict mismatch. Expected {}, got {}", 
                    test.name, test.expected_verdict, actual_verdict);
            }
        }
    }
}
