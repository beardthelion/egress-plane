pub struct Api;

impl Api {
    pub fn get(&self, path: &str) -> reqwest::Result<reqwest::blocking::Response> {
        reqwest::blocking::get(path)
    }
}
