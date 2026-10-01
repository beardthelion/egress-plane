pub fn connect() {
    let _ = std::net::TcpStream::connect("api.example.com:443");
}
