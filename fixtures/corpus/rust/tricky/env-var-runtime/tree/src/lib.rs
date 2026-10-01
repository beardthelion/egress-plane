pub fn fetch() -> reqwest::Result<reqwest::blocking::Response> {
    let url = std::env::var("API_URL").unwrap();
    reqwest::blocking::get(url)
}
