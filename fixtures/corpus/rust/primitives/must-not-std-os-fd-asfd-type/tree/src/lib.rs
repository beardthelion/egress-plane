pub fn probe() {
    let _ = (
        std::os::fd::AsFd,
        std::os::fd::AsRawFd,
        std::os::fd::BorrowedFd,
        std::os::fd::FromRawFd,
        std::os::fd::IntoRawFd,
        std::os::fd::OwnedFd,
        std::os::fd::RawFd,
        std::os::fd::STDERR,
        std::os::fd::STDIN,
        std::os::fd::STDOUT,
    );
}
