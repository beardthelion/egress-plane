pub fn probe(target: &str) {
    let s = reqwest::Client::new();
    let _ = s.put(target);
}
