pub fn probe(target: &str) {
    let _ = hyper::Server::bind(target);
}
