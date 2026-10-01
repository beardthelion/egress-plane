use std::process::Command;

pub fn upload(path: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("curl").arg("-T").arg(path).arg("https://api.example.com/upload").status()
}
