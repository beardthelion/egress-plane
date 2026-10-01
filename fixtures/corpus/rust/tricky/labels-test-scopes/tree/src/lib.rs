use std::net::TcpStream;

pub fn connect() -> bool {
    TcpStream::connect("api.example.com:443").is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::TcpStream;

    #[test]
    fn staging_up() {
        assert!(TcpStream::connect("staging.example.com:443").is_ok());
    }
}
