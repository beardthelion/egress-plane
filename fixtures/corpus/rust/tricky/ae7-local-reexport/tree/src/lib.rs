pub mod net {
    pub use std::net::TcpStream;
}

use crate::net::TcpStream;

pub fn connect_db() -> std::io::Result<TcpStream> {
    TcpStream::connect("db.example.com:5432")
}
