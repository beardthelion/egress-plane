pub fn probe(target: &str) {
    let _ = attohttpc::post(target);
}
