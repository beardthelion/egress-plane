pub fn probe() {
    let _ = (
        std::net::TcpListener,
        std::net::TcpStream,
        std::net::UdpSocket,
    );
}
