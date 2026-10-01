pub fn connect() -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect(("api.example.com", 443))
}
