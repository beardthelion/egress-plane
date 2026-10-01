pub fn probe() {
    unsafe {
        let _ = libc::socket();
    }
}
