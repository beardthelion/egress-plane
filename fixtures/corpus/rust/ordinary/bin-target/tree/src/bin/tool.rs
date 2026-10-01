use std::process::Command;

fn main() {
    let _ = Command::new("git").arg("pull").status();
}
