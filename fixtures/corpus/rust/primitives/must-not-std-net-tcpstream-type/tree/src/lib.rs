pub fn probe() {
    let _ = (
        std::net::TcpStream,
        std::net::TcpListener,
        std::net::UdpSocket,
    );
}
