pub fn probe(target: &str) {
    let _ = tokio::process::Command::new(target);
}
