use crate::shared::rules::{Rule, CompositeRule, RhaiRule, builders, create_rhai_engine, RuleMeta};
use crate::shared::scoring::SignalCategory;
use std::fs;
use std::path::{Path, PathBuf};
use rhai::Engine;

use std::sync::Arc;

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules = rhai_rules();
    rules.extend(hardcoded_rules());
    rules.extend(composite_rules());
    rules
}

fn rhai_rules() -> Vec<Box<dyn Rule>> {
    let rules_dir = Path::new("rules");
    if !rules_dir.exists() {
        return Vec::new();
    }

    let engine = create_rhai_engine();

    iter_rhai_scripts(rules_dir)
        .filter_map(|(family, path)| compile_rule(engine.clone(), family, path))
        .collect()
}

fn iter_rhai_scripts(root: &Path) -> impl Iterator<Item = (String, PathBuf)> {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .flat_map(|family_dir| {
            let family = family_dir.file_name().to_string_lossy().into_owned();
            println!("DEBUG: Visiting family: {}", family);
            fs::read_dir(family_dir.path())
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |x| x == "rhai"))
                .map(move |e| (family.clone(), e.path()))
                .collect::<Vec<_>>()
        })
}

fn family_to_category(family: &str) -> SignalCategory {
    match family {
        "pkgbuild" | "malware" | "gtfobins" => SignalCategory::Pkgbuild,
        "reputation" | "network" | "persistence" => SignalCategory::Behavioral,
        "metadata" => SignalCategory::Metadata,
        _ => SignalCategory::Behavioral,
    }
}

fn compile_rule(engine: Arc<Engine>, family: String, path: PathBuf) -> Option<Box<dyn Rule>> {
    let content = fs::read_to_string(&path).ok()?;
    match engine.compile(&content) {
        Ok(ast) => {
            let id = path.file_stem()?.to_str()?.to_uppercase();
            let meta = parse_metadata(&content);
            let category = meta.category.unwrap_or(family_to_category(&family));

            Some(Box::new(RhaiRule {
                id: format!("R-{}", id),
                description: meta.description,
                category,
                salience: meta.salience,
                ast,
                engine,
            }))
        }
        Err(e) => {
            println!("DEBUG: Failed to compile Rhai rule {:?}: {}", path, e);
            None
        }
    }
}

fn parse_metadata(content: &str) -> RuleMeta {
    content.lines()
        .take_while(|l| l.starts_with("//"))
        .fold(RuleMeta::default(), |mut meta, line| {
            if let Some(v) = line.strip_prefix("// Description:") {
                meta.description = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("// Agenda:") {
                meta.agenda = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("// Salience:") {
                meta.salience = v.trim().parse().unwrap_or(500);
            }
            meta
        })
}

fn hardcoded_rules() -> Vec<Box<dyn Rule>> {
    Vec::new()
}

fn composite_rules() -> Vec<Box<dyn Rule>> {
    use crate::shared::rules::Verdict;
    vec![
        Box::new(CompositeRule {
            id: "C-DOWNLOAD-CHMOD-EXEC".to_string(),
            description: "Download, chmod +x, and execution chain detected".to_string(),
            category: SignalCategory::Pkgbuild,
            salience: 500,
            verdict: Verdict::Suspicious,
            condition: builders::check_chain(vec![
                r"(curl|wget)\s",
                r"chmod\s+.*?\+x",
                r"\./\S+"
            ]),
        }),
    ]
}
