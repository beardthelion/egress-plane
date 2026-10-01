pub fn probe(target: &str) {
    let _ = std::net::TcpListener::bind(target);
}
