pub fn probe(target: &str) {
    let s = reqwest::blocking::Client::new();
    let _ = s.get(target);
}
