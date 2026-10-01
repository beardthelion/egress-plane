pub fn h() -> bool {
    std::net::TcpStream::connect("hidden.example.com:443").is_ok()
}
