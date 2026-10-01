use std::collections::HashMap;
use std::fmt::Write;

pub fn summarize(words: &[&str]) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for w in words {
        *counts.entry(w).or_insert(0) += 1;
    }
    let mut out = String::new();
    let _ = write!(out, "{}", counts.len());
    out
}
