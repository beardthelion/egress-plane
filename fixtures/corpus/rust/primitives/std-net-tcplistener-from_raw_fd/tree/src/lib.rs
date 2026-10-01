use std::os::fd::FromRawFd;

pub fn probe() {
    unsafe {
        let _ = std::net::TcpListener::from_raw_fd(3);
    }
}
