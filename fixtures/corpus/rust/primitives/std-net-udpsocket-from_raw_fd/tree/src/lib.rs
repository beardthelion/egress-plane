use std::os::fd::FromRawFd;

pub fn probe() {
    unsafe {
        let _ = std::net::UdpSocket::from_raw_fd(3);
    }
}
