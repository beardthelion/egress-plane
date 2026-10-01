pub fn probe(target: &str) {
    let _ = attohttpc::delete(target);
}
