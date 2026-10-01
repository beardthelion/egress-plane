pub fn probe(target: &str) {
    let _ = attohttpc::head(target);
}
