pub fn probe() {
    let _ = std::os::unix::net::UnixStream::connect_addr();
}
