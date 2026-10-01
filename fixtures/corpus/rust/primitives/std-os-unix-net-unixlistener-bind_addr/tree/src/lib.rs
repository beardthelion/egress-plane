pub fn probe() {
    let _ = std::os::unix::net::UnixListener::bind_addr();
}
