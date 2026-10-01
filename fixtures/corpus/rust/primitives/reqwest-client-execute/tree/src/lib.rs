pub fn probe() {
    let s = reqwest::Client::new();
    let _ = s.execute();
}
