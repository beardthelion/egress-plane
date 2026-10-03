mod chain;
mod m;

mod inline {
    pub type Sock = std::net::TcpStream;
}

use crate::m::T;

pub fn used() -> std::io::Result<T> {
    T::connect("xalias-used.example.com:443")
}

pub fn qualified() -> std::io::Result<m::T> {
    m::Hidden::connect("xalias-qualified.example.com:443")
}

pub fn nested() -> std::io::Result<inline::Sock> {
    inline::Sock::connect("xalias-inline.example.com:443")
}

pub fn chained() -> std::io::Result<chain::Far> {
    chain::Far::connect("xalias-chain.example.com:443")
}

pub fn inert() -> usize {
    let _ = m::Mine::connect("not-egress.example.com:443");
    m::Text::from("also-not-egress.example.com").len()
}
