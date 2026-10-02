pub fn probe(target: &str) {
    unsafe {
        let _ = libloading::Library::new(target);
    }
}
