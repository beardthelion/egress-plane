pub fn probe() {
    unsafe {
        let _ = std::net::TcpStream::from_raw_socket(3);
    }
}
