pub fn probe(target: &str) {
    let _ = isahc::get(target);
}
