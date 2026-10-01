pub mod net {
    use std::net::TcpStream;

    pub fn ping() -> bool {
        TcpStream::connect("api.example.com:80").is_ok()
    }
}
