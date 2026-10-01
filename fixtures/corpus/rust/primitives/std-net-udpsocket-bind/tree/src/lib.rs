pub fn probe(target: &str) {
    let _ = std::net::UdpSocket::bind(target);
}
