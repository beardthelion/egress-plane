pub fn probe(target: &str) {
    let _ = attohttpc::get(target);
}
