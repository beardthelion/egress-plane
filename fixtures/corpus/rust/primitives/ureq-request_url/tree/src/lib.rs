pub fn probe(target: &str) {
    let _ = ureq::request_url(Default::default(), target);
}
