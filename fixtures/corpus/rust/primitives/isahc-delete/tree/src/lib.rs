pub fn probe(target: &str) {
    let _ = isahc::delete(target);
}
