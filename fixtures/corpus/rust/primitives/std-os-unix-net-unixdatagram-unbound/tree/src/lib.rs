pub fn probe() {
    let _ = std::os::unix::net::UnixDatagram::unbound();
}
