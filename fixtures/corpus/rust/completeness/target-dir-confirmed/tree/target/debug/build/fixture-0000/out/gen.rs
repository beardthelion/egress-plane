pub fn g() -> bool {
    std::net::TcpStream::connect("gen.example.com:443").is_ok()
}
