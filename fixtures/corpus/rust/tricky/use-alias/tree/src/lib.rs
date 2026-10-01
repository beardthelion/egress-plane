use reqwest::blocking::get as http_get;
use std::process::Command as Cmd;

pub fn fetch() -> reqwest::Result<reqwest::blocking::Response> {
    http_get("https://api.example.com/alias")
}

pub fn tunnel() -> std::io::Result<std::process::Child> {
    Cmd::new("ssh").arg("bastion.example.com").spawn()
}
