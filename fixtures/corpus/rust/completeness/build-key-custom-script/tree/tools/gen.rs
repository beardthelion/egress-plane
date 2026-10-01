use std::process::Command;

fn main() {
    let _ = Command::new("protoc").arg("--version").status();
}
