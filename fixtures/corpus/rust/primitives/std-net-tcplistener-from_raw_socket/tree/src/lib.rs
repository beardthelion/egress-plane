pub fn probe() {
    unsafe {
        let _ = std::net::TcpListener::from_raw_socket(3);
    }
}
