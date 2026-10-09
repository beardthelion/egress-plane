#[test]
fn ignored() {
    let _ = std::net::TcpStream::connect("tests-sentinel-zz.example:1");
}
