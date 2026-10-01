pub fn probe(target: &str) {
    let _ = isahc::head_async(target);
}
