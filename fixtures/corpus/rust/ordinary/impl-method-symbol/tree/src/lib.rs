pub struct Api;

impl Api {
    pub fn fetch(&self) -> reqwest::Result<reqwest::blocking::Response> {
        reqwest::blocking::get("https://api.example.com/me")
    }
}
