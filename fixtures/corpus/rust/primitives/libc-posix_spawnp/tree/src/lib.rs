pub fn probe() {
    unsafe {
        let _ = libc::posix_spawnp();
    }
}
