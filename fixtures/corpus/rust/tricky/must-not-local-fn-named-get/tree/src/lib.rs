pub fn get(url: &str) -> usize {
    url.len()
}

pub fn connect(addr: &str) -> bool {
    !addr.is_empty()
}

pub fn run() -> usize {
    let _ = connect("api.example.com:443");
    get("https://api.example.com/not-a-request")
}
