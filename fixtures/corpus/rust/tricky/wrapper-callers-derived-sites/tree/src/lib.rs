pub fn get_json(url: String) -> reqwest::Result<reqwest::blocking::Response> {
    reqwest::blocking::get(url)
}

pub fn users() -> reqwest::Result<reqwest::blocking::Response> {
    crate::get_json("https://a.invalid/users".to_string())
}

pub fn hook() -> reqwest::Result<reqwest::blocking::Response> {
    crate::get_json(std::env::var("HOOK").unwrap_or_default())
}

pub fn computed(name: &str) -> reqwest::Result<reqwest::blocking::Response> {
    crate::get_json(format!("https://{name}.invalid"))
}
