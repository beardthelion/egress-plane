pub fn get() -> bool {
    std::net::TcpStream::connect("vendored.example.com:80").is_ok()
}
