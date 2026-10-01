pub fn fetch() -> reqwest::Result<reqwest::blocking::Response> {
    let url = env!("API_URL");
    reqwest::blocking::get(url)
}
