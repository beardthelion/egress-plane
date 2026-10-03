pub type T = std::net::TcpStream;
pub(crate) type Hidden = std::net::TcpStream;

pub struct Conn;

impl Conn {
    pub fn connect(_addr: &str) -> Self {
        Conn
    }
}

pub type Mine = Conn;
pub type Text = String;
