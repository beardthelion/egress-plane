mod chain;
mod local;

use std::net::TcpStream;

type T = std::net::TcpStream;
pub type U = TcpStream;

pub fn one() -> std::io::Result<T> {
    T::connect("typealias-one.example.com:443")
}

pub fn two() -> std::io::Result<U> {
    U::connect("typealias-two.example.com:443")
}

struct Conn;

impl Conn {
    fn connect(_addr: &str) -> Self {
        Conn
    }
}

type Mine = Conn;
type Text = std::string::String;

pub fn inert() -> usize {
    let _ = Mine::connect("not-egress.example.com:443");
    Text::from("also-not-egress.example.com").len()
}
