pub fn probe(target: &str) {
    let s = ureq::Agent::new();
    let _ = s.delete(target);
}
