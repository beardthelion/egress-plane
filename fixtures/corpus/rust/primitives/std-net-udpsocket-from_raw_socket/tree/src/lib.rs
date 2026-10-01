pub fn probe() {
    unsafe {
        let _ = std::net::UdpSocket::from_raw_socket(3);
    }
}
