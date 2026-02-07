# Tests

## Strategy

- **Feature tests** (`feature_tests.rs`): Unit tests per feature using fixture PKGBUILDs
- **Integration tests** (`integration_tests.rs`): End-to-end scan tests that verify full pipeline

## Fixtures

- `fixtures/malicious/` — PKGBUILDs based on known attacks (CHAOS RAT, Xeactor patterns, synthetic examples)
- `fixtures/benign/` — PKGBUILDs from popular, trusted packages

## Running

```bash
cargo test
```

## Adding test cases

1. Place a PKGBUILD file in `fixtures/malicious/` or `fixtures/benign/`
2. Name it descriptively (e.g., `curl_pipe_bash.PKGBUILD`, `firefox_normal.PKGBUILD`)
3. Write a test that loads the fixture and asserts expected signals/tier
