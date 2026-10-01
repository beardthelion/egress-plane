pub fn probe(target: &str) {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let _ = s.connect(target);
}
