pub fn c() -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::get("https://ci:hunter2@api.example.com/c")
}
