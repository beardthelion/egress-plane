use std::os::fd::FromRawFd;

pub fn probe() {
    unsafe {
        let _ = std::os::unix::net::UnixDatagram::from_raw_fd(3);
    }
}
