pub fn probe() {
    unsafe {
        let _ = libloading::os::unix::Library::open(target, 0);
    }
}
