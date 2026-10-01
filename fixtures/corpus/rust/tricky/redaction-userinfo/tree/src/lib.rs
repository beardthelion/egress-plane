pub fn hook() -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::get("https://deploy:hunter2@api.example.com/hook")
}
