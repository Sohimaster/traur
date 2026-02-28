use crate::shared::models::PackageContext;
use crate::shared::scoring::SignalCategory;
use regex::Regex;
use serde::Deserialize;
use rhai::{Engine, Dynamic, Scope, AST};
use std::sync::Arc;

/// Verdict levels for rules (highest to lowest priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
pub enum Verdict {
    Malicious,
    Suspicious,
    Ok,
    Trusted,
}

impl Verdict {
}

/// Risk levels for rules, replacing simple point scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn to_points(&self) -> u32 {
        match self {
            Severity::None => 0,
            Severity::Low => 15,
            Severity::Medium => 40,
            Severity::High => 75,
            Severity::Critical => 95,
        }
    }

    pub fn from_score(score: f64) -> Self {
        let abs_score = score.abs();
        if abs_score >= 0.9 { Severity::Critical }
        else if abs_score >= 0.7 { Severity::High }
        else if abs_score >= 0.4 { Severity::Medium }
        else if abs_score >= 0.1 { Severity::Low }
        else { Severity::None }
    }
}

/// A detection result from a single rule evaluation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Detection {
    pub rule_id: String,
    pub verdict: Verdict,
    pub category: SignalCategory,
    pub salience: u32, // 0-1000, higher = evaluated first
    pub description: String,
    pub matched_line: Option<String>,
}

#[derive(Debug, Default)]
pub struct RuleMeta {
    pub agenda: String,
    pub description: String,
    pub category: Option<SignalCategory>,
    pub salience: u32, // 0-1000, higher = evaluated first
}

/// The base trait for all detection rules.
pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn category(&self) -> SignalCategory;
    fn salience(&self) -> u32; // Default 500 for unspecified
    fn evaluate(&self, ctx: &PackageContext) -> Vec<Detection>;
}

/// A rule implemented in Rhai scripting language.
pub struct RhaiRule {
    pub id: String,
    pub description: String,
    pub category: SignalCategory,
    pub salience: u32,
    pub ast: AST,
    pub engine: Arc<Engine>,
}

impl Rule for RhaiRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> SignalCategory {
        self.category
    }

    fn salience(&self) -> u32 {
        self.salience
    }

    fn evaluate(&self, ctx: &PackageContext) -> Vec<Detection> {
        let mut scope = Scope::new();
        
        // Build context object for Rhai
        let mut ctx_obj = rhai::Map::new();
        ctx_obj.insert("name".into(), ctx.name.clone().into());
        ctx_obj.insert("pkgbuild_content".into(), ctx.pkgbuild_content.clone().unwrap_or_default().into());
        ctx_obj.insert("install_script_content".into(), ctx.install_script_content.clone().unwrap_or_default().into());
        ctx_obj.insert("prior_pkgbuild_content".into(), ctx.prior_pkgbuild_content.clone().unwrap_or_default().into());
        ctx_obj.insert("github_stars".into(), ctx.github_stars.map(|s| s as i64).unwrap_or(-1).into());
        ctx_obj.insert("github_not_found".into(), ctx.github_not_found.into());
        
        let mut comments = rhai::Array::new();
        for comment in &ctx.aur_comments {
            comments.push(comment.clone().into());
        }
        ctx_obj.insert("aur_comments".into(), comments.into());

        if let Some(ref meta) = ctx.metadata {
            let mut meta_obj = rhai::Map::new();
            meta_obj.insert("name".into(), meta.name.clone().into());
            meta_obj.insert("package_base".into(), meta.package_base.clone().unwrap_or_default().into());
            meta_obj.insert("url".into(), meta.url.clone().unwrap_or_default().into());
            meta_obj.insert("num_votes".into(), (meta.num_votes as i64).into());
            meta_obj.insert("votes".into(), (meta.num_votes as i64).into()); // Alias for backward compat
            meta_obj.insert("popularity".into(), meta.popularity.into());
            meta_obj.insert("out_of_date".into(), meta.out_of_date.map(|t| t as i64).unwrap_or(-1).into());
            meta_obj.insert("maintainer".into(), meta.maintainer.clone().unwrap_or_default().into());
            meta_obj.insert("submitter".into(), meta.submitter.clone().unwrap_or_default().into());
            meta_obj.insert("first_submitted".into(), (meta.first_submitted as i64).into());
            
            let mut licenses = rhai::Array::new();
            if let Some(ref lics) = meta.license {
                for lic in lics {
                    licenses.push(lic.clone().into());
                }
            }
            meta_obj.insert("license".into(), licenses.into());
            
            ctx_obj.insert("metadata".into(), meta_obj.into());
        } else {
            ctx_obj.insert("metadata".into(), Dynamic::UNIT);
        }

        // Maintainer packages
        let mut maint_pkgs = rhai::Array::new();
        for pkg in &ctx.maintainer_packages {
            let mut p_obj = rhai::Map::new();
            p_obj.insert("name".into(), pkg.name.clone().into());
            p_obj.insert("num_votes".into(), (pkg.num_votes as i64).into());
            p_obj.insert("popularity".into(), pkg.popularity.into());
            maint_pkgs.push(p_obj.into());
        }
        ctx_obj.insert("maintainer_packages".into(), maint_pkgs.into());

        // Git log
        let mut git_log = rhai::Array::new();
        for commit in &ctx.git_log {
            let mut c_obj = rhai::Map::new();
            c_obj.insert("hash".into(), commit.hash.clone().into());
            c_obj.insert("author".into(), commit.author.clone().into());
            c_obj.insert("timestamp".into(), (commit.timestamp as i64).into());
            c_obj.insert("diff".into(), commit.diff.clone().unwrap_or_default().into());
            git_log.push(c_obj.into());
        }
        ctx_obj.insert("git_log".into(), git_log.into());

        // Call 'scan' function as per minimal architecture
        let result: Dynamic = self.engine.call_fn(&mut scope, &self.ast, "scan", (ctx_obj,))
            .unwrap_or_else(|e| {
                eprintln!("Error evaluating Rhai rule {}: {}", self.id, e);
                Dynamic::UNIT
            });

        if !result.is_unit() {
            println!("DEBUG: Rule {} returned result: {:?}", self.id, result);
        }

        // Parse result: supports #{verdict, category, salience, reason} map or Array of maps
        if result.is::<rhai::Map>() {
            let map = result.cast::<rhai::Map>();
            if let Some(det) = self.map_to_detection(&map) { return vec![det]; }
        } else if result.is::<rhai::Array>() {
            let arr = result.cast::<rhai::Array>();
            return arr.iter().filter_map(|v| {
                if v.is::<rhai::Map>() {
                    let map = v.clone().cast::<rhai::Map>();
                    self.map_to_detection(&map)
                } else { None }
            }).collect();
        }

        Vec::new()
    }
}

impl RhaiRule {
    fn map_to_detection(&self, map: &rhai::Map) -> Option<Detection> {
        let id = map.get("id")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_else(|| self.id.clone());
            
        let verdict = if let Some(v) = map.get("verdict") {
            let verdict_str = v.clone().into_string().ok()?;
            match verdict_str.to_lowercase().as_str() {
                "malicious" => Verdict::Malicious,
                "suspicious" => Verdict::Suspicious,
                "ok" => Verdict::Ok,
                "trusted" => Verdict::Trusted,
                _ => return None,
            }
        } else if let Some(s) = map.get("score") {
            let score = s.clone().as_float().unwrap_or(0.0);
            if score >= 0.9 { Verdict::Malicious }
            else if score >= 0.4 { Verdict::Suspicious }
            else { Verdict::Ok }
        } else {
            return None;
        };

        let category = if let Some(c) = map.get("category") {
            let category_str = c.clone().into_string().ok()?;
            match category_str.to_lowercase().as_str() {
                "metadata" => SignalCategory::Metadata,
                "pkgbuild" => SignalCategory::Pkgbuild,
                "behavioral" => SignalCategory::Behavioral,
                "temporal" => SignalCategory::Temporal,
                _ => self.category,
            }
        } else {
            self.category
        };

        let salience = map.get("salience")
            .and_then(|v| v.clone().as_int().ok())
            .map(|s| s as u32)
            .unwrap_or_else(|| {
                // If inferred from score, use score for salience too
                if let Some(s) = map.get("score") {
                    (s.clone().as_float().unwrap_or(0.5) * 1000.0) as u32
                } else {
                    500
                }
            });

        let reason = map.get("reason")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_else(|| {
                map.get("description")
                    .and_then(|v| v.clone().into_string().ok())
                    .unwrap_or_else(|| self.description.clone())
            });
        
        Some(Detection {
            rule_id: id,
            verdict,
            category,
            salience,
            description: reason,
            matched_line: None,
        })
    }
}

pub fn create_rhai_engine() -> Arc<Engine> {
    let mut engine = Engine::new();
    
    // Security Sandboxing
    engine.set_max_operations(50_000);
    engine.set_max_string_size(2_000);
    engine.set_max_expr_depths(50, 50);
    // Filesystem and module imports are disabled by default in Rhai 
    // unless a module resolver is explicitly provided.
    
    // Register helper functions
    engine.register_fn("is_trusted_domain", |url: String| {
        let trusted = ["github.com", "gitlab.com", "archlinux.org"];
        trusted.iter().any(|&d| url.contains(d))
    });

    engine.register_fn("levenshtein", |s1: String, s2: String| -> i64 {
        strsim::levenshtein(&s1, &s2) as i64
    });

    engine.register_fn("now_timestamp", || -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    });

    engine.register_fn("extract_domain", |url: String| -> String {
        let after_scheme = url.split("://").nth(1).unwrap_or("");
        let host = after_scheme.split('/').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("");
        host.to_lowercase()
    });

    engine.register_fn("extract_github_org", |url: String| -> String {
        let after_scheme = url.split("://").nth(1).unwrap_or("");
        let host = after_scheme.split('/').next().unwrap_or("");
        if !host.to_lowercase().contains("github.com") { return "".to_string(); }
        let path_part = after_scheme.split('/').nth(1).unwrap_or("");
        path_part.to_lowercase()
    });

    engine.register_fn("find_regex", |text: String, pattern: String| -> String {
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(caps) = re.captures(&text) {
                return caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| caps.get(0).unwrap().as_str().to_string());
            }
        }
        "".to_string()
    });

    engine.register_fn("test_regex", |text: String, pattern: String| -> bool {
        if let Ok(re) = Regex::new(&pattern) {
            return re.is_match(&text);
        }
        false
    });

    // match_patterns(text, category) helper
    engine.register_fn("match_patterns", |text: String, category: String| -> rhai::Array {
        let patterns = crate::shared::patterns::load_patterns(&category);
        let mut detections = rhai::Array::new();
        
        let cat_enum = match category.to_lowercase().as_str() {
            "metadata" => SignalCategory::Metadata,
            "pkgbuild" | "pkgbuild_analysis" => SignalCategory::Pkgbuild,
            "behavioral" | "shell_analysis" => SignalCategory::Behavioral,
            "temporal" => SignalCategory::Temporal,
            _ => SignalCategory::Pkgbuild,
        };
        let cat_str = format!("{:?}", cat_enum);

        for pat in patterns {
            if pat.regex.is_match(&text) {
                let mut map = rhai::Map::new();
                map.insert("id".into(), pat.id.into());
                let score = pat.points as f64 / 100.0;
                map.insert("score".into(), score.into());
                map.insert("reason".into(), pat.description.into());
                map.insert("category".into(), cat_str.clone().into());
                
                let verdict = if score >= 0.9 { "malicious" }
                else if score >= 0.4 { "suspicious" }
                else { "ok" };
                map.insert("verdict".into(), verdict.into());
                
                detections.push(map.into());
            }
        }
        detections
    });

    Arc::new(engine)
}

/// A rule that combines multiple other rules with logical conditions.
pub struct CompositeRule {
    pub id: String,
    pub description: String,
    pub category: SignalCategory,
    pub salience: u32,
    pub verdict: Verdict,
    pub condition: Box<dyn Fn(&PackageContext) -> bool + Send + Sync>,
}

impl Rule for CompositeRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> SignalCategory {
        self.category
    }

    fn salience(&self) -> u32 {
        self.salience
    }

    fn evaluate(&self, ctx: &PackageContext) -> Vec<Detection> {
        if (self.condition)(ctx) {
            vec![Detection {
                rule_id: self.id.clone(),
                verdict: self.verdict,
                category: self.category,
                salience: self.salience,
                description: self.description.clone(),
                matched_line: None,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Helper for building common composite rules.
pub mod builders {
    use super::*;

    pub fn check_chain(patterns: Vec<&str>) -> Box<dyn Fn(&PackageContext) -> bool + Send + Sync> {
        let regexes: Vec<Regex> = patterns.into_iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
            
        Box::new(move |ctx| {
            let Some(ref content) = ctx.pkgbuild_content else { return false };
            let mut last_index = 0;
            for re in &regexes {
                if let Some(m) = re.find(&content[last_index..]) {
                    last_index += m.end();
                } else {
                    return false;
                }
            }
            true
        })
    }
}
