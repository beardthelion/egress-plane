pub fn probe() {
    unsafe {
        let _ = libc::system();
    }
}
