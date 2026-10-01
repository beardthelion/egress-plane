pub fn probe(target: &str) {
    let _ = std::net::TcpStream::connect_timeout(target);
}
