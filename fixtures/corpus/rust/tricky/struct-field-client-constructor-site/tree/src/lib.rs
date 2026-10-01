pub struct Api {
    client: reqwest::blocking::Client,
}

impl Api {
    pub fn new() -> Self {
        Api { client: reqwest::blocking::Client::new() }
    }

    pub fn users(&self) -> reqwest::Result<reqwest::blocking::Response> {
        self.client.get("https://api.example.com/users").send()
    }
}
