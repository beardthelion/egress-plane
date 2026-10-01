fn main() {
    let body = reqwest::blocking::get("https://api.example.com/status").unwrap().text().unwrap();
    let _ = body;
}
