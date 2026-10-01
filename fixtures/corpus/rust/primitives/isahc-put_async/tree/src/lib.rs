pub fn probe(target: &str) {
    let _ = isahc::put_async(target);
}
