pub fn probe(target: &str) {
    unsafe {
        let _ = libloading::os::unix::Library::new(target);
    }
}
