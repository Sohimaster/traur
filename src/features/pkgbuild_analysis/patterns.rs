use crate::shared::patterns::{load_patterns, CompiledPattern};
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

pub fn compiled_patterns() -> &'static Vec<CompiledPattern> {
    PATTERNS.get_or_init(|| load_patterns("pkgbuild_analysis"))
}
