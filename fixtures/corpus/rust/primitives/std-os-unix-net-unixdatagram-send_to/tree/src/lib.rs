pub fn probe(target: &str) {
    let s = std::os::unix::net::UnixDatagram::unbound().unwrap();
    let _ = s.send_to(Default::default(), target);
}
