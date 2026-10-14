pub fn probe() {
    let _ = (
        std::os::unix::net::UnixDatagram,
        std::os::unix::net::UnixListener,
        std::os::unix::net::UnixStream,
    );
}
