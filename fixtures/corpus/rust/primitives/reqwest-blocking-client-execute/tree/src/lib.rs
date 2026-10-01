pub fn probe() {
    let s = reqwest::blocking::Client::new();
    let _ = s.execute();
}
