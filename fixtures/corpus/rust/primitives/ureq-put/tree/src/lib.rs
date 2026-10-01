pub fn probe(target: &str) {
    let _ = ureq::put(target);
}
