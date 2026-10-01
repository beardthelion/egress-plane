pub fn probe(target: &str) {
    let _ = ureq::delete(target);
}
