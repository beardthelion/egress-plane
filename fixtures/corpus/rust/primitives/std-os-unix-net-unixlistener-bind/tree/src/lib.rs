pub fn probe(target: &str) {
    let _ = std::os::unix::net::UnixListener::bind(target);
}
