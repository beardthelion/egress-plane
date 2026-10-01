const API: &str = "https://api.example.com/v2";

pub fn fetch() -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::get(API)
}
