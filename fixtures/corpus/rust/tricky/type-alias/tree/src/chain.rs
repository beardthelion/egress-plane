type A0 = std::net::TcpStream;
type A1 = A0;
type A2 = A1;
type A3 = A2;
type A4 = A3;
type A5 = A4;
type A6 = A5;
type A7 = A6;
type A8 = A7;
type A9 = A8;

pub fn far() -> std::io::Result<A0> {
    A9::connect("typealias-far.example.com:443")
}
