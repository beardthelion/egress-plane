pub fn fetch() -> http_client::Result<http_client::blocking::Response> {
    http_client::blocking::get("https://api.example.com/renamed")
}
