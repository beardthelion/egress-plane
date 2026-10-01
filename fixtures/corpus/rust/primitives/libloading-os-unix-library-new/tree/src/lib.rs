pub fn probe() {
    unsafe {
        let _ = libloading::os::unix::Library::new(target);
    }
}
