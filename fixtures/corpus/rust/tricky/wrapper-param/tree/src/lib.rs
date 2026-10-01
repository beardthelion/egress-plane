pub fn get_json(url: &str) -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::get(url)
}

pub fn users() -> reqwest::Result<reqwest::blocking::Response> {
    get_json("https://api.example.com/users")
}

pub fn teams() -> reqwest::Result<reqwest::blocking::Response> {
    get_json("https://api.example.com/teams")
}
