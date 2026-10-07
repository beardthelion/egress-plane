pub fn probe() {
    let _ = (
        libc::c_Example,
        libc::size_t,
        libc::ssize_t,
        libc::pid_t,
        libc::uid_t,
        libc::gid_t,
        libc::off_t,
        libc::mode_t,
        libc::socklen_t,
        libc::sockaddr,
        libc::sockaddr_in,
        libc::sockaddr_in6,
        libc::sockaddr_un,
        libc::AF_Example,
        libc::SOCK_Example,
        libc::IPPROTO_Example,
        libc::O_Example,
        libc::SIGExample,
        libc::EExample,
    );
}
