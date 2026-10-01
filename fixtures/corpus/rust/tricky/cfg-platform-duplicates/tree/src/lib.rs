#[cfg(unix)]
pub fn ping() -> bool {
    std::net::TcpStream::connect("api.example.com:443").is_ok()
}

#[cfg(not(unix))]
pub fn ping() -> bool {
    std::net::TcpStream::connect("api.example.com:443").is_ok()
}
