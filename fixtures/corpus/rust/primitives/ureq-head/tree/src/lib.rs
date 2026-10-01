pub fn probe(target: &str) {
    let _ = ureq::head(target);
}
