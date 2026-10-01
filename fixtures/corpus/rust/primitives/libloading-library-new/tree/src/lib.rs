pub fn probe() {
    unsafe {
        let _ = libloading::Library::new(target);
    }
}
