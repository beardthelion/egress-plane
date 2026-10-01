pub fn probe(target: &str) {
    let _ = isahc::post_async(target);
}
