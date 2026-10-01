pub fn probe(target: &str) {
    let _ = ureq::request(Default::default(), target);
}
