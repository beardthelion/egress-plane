pub fn probe(target: &str) {
    unsafe {
        let _ = libloading::os::unix::Library::open(target, 0);
    }
}
