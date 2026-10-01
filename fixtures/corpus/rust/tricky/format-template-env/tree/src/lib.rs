pub fn items() -> reqwest::Result<reqwest::blocking::Response> {
    let base = env!("API_BASE");
    let url = format!("{base}/v1/items");
    reqwest::blocking::get(url)
}
