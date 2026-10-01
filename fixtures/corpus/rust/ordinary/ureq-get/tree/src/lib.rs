pub fn status() -> Result<ureq::Response, ureq::Error> {
    ureq::get("https://api.example.com/status").call()
}
