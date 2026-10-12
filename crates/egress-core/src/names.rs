//! Name signals (KTD17): the declaring distribution of a Python import
//! name. The signal annotates dependency entries only; it never changes
//! the completeness state or the exit code (R19).
//!
//! Sources, in order:
//!
//! 1. Installed metadata in a named Python root: a distribution whose
//!    `RECORD` top-level paths or `top_level.txt` names the import (the
//!    inventory merge, so `Instance::imports`).
//! 2. The embedded curated table `data/python-distributions.toml`,
//!    filtered by the project declarations read on every scan
//!    (`pyproject.toml`, `setup.cfg`, `requirements*.txt`): with at
//!    least one declaration, curated candidates not declared are
//!    dropped; with none, every curated candidate is kept.
//!
//! Names compare after PEP 503 normalization and are emitted as
//! declared (or as the table spells them when undeclared). Several
//! candidates give a sorted list, never a guess.

use std::collections::{BTreeMap, BTreeSet};

use crate::data::DistributionMapping;
use crate::deps::inventory::Inventory;
use crate::deps::version::pep503;
use crate::model::{DistributionSource, Language, UnscannedDependency};

/// The declaring distributions of one Python import name plus where
/// they came from. An empty list with `None` means the name could not
/// be attributed.
pub fn python_distribution(
    import: &str,
    inventories: &[Inventory],
    declared: &[String],
    table: &[DistributionMapping],
) -> (Vec<String>, Option<DistributionSource>) {
    // Installed metadata wins: a usable distribution instance in a
    // named Python root that provides this import.
    let mut installed: Vec<String> = inventories
        .iter()
        .flat_map(|i| i.instances.iter())
        .filter(|i| i.flags.unsupported.is_none())
        .filter(|i| i.imports.iter().any(|n| n == import))
        .filter_map(|i| i.distribution.clone())
        .filter(|d| !d.is_empty())
        .collect();
    installed.sort();
    installed.dedup();
    if !installed.is_empty() {
        return (installed, Some(DistributionSource::InstalledMetadata));
    }
    let Some(mapping) = table.iter().find(|m| m.import == import) else {
        return (Vec::new(), None);
    };
    // Normalized declaration to the spelling the declaration used;
    // the first spelling wins when several normalize alike.
    let mut declared_map: BTreeMap<String, &str> = BTreeMap::new();
    for d in declared {
        declared_map.entry(pep503(d)).or_insert(d.as_str());
    }
    let mut out: Vec<String> = mapping
        .distributions
        .iter()
        .filter_map(|c| {
            if declared_map.is_empty() {
                Some(c.clone())
            } else {
                declared_map.get(&pep503(c)).map(|s| (*s).to_string())
            }
        })
        .collect();
    out.sort();
    out.dedup();
    if out.is_empty() {
        (out, None)
    } else {
        (out, Some(DistributionSource::Curated))
    }
}

/// Applies the signal to top-level unscanned Python entries.
pub fn apply_unscanned(
    entries: &mut [UnscannedDependency],
    inventories: &[Inventory],
    declared: &[String],
    table: &[DistributionMapping],
) {
    for e in entries
        .iter_mut()
        .filter(|e| e.language == Language::Python)
    {
        let (distribution, source) = python_distribution(&e.package, inventories, declared, table);
        e.distribution = distribution;
        e.distribution_source = source;
    }
}

// ---- KTD18: confusable and mixed-script marking -----------------------------

use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;
use unicode_security::mixed_script::MixedScript;

use crate::model::{DependencyMark, MarkRule};

/// The mark for one dependency name. `comparison` holds catalogued
/// package names, standard-library module names, and the other
/// dependency names of this language in the report. ASCII names are
/// never marked; NFC-equal spellings never resemble each other.
pub fn dependency_mark(
    lang: Language,
    name: &str,
    comparison: &BTreeSet<String>,
) -> Option<DependencyMark> {
    if name.is_ascii() {
        return None;
    }
    let mut rules = Vec::new();
    let mut resembles: BTreeSet<String> = BTreeSet::new();
    match lang {
        Language::Javascript | Language::Rust => rules.push(MarkRule::NonAsciiName),
        Language::Python => {}
    }
    if lang == Language::Python && !name.is_single_script() {
        rules.push(MarkRule::MixedScript);
    }
    // The confusable rule: equal skeleton, different NFC spelling.
    let own_nfc: String = name.nfc().collect();
    let own_skel: String = skeleton(name).collect();
    for other in comparison {
        if *other == name {
            continue;
        }
        let other_skel: String = skeleton(other).collect();
        if other_skel == own_skel && other.nfc().collect::<String>() != own_nfc {
            resembles.insert(other.clone());
        }
    }
    if !resembles.is_empty() {
        rules.push(MarkRule::ConfusableSkeleton);
    }
    if rules.is_empty() {
        return None;
    }
    rules.sort();
    rules.dedup();
    Some(DependencyMark {
        rules,
        resembles: resembles.into_iter().collect(),
    })
}
