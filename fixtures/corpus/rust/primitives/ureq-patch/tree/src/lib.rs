pub fn probe(target: &str) {
    let _ = ureq::patch(target);
}
