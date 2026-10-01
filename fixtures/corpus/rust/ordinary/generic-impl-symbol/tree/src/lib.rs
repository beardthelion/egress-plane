use std::marker::PhantomData;
use std::net::TcpStream;

pub struct Store<T> {
    _t: PhantomData<T>,
}

impl<T> Store<T> {
    pub fn sync(&self) -> bool {
        TcpStream::connect("store.example.com:6379").is_ok()
    }
}
