pub fn probe(target: &str) {
    let _ = isahc::head(target);
}
