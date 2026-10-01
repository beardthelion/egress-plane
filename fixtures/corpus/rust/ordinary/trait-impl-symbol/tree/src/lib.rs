use std::net::TcpStream;

pub trait Probe {
    fn probe(&self) -> bool;
}

pub struct Remote;

impl Probe for Remote {
    fn probe(&self) -> bool {
        TcpStream::connect("api.example.com:443").is_ok()
    }
}
