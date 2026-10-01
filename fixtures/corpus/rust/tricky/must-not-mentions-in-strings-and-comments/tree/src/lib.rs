//! Talks to the server through std::net::TcpStream::connect in another crate.

/// Run `reqwest::get("https://api.example.com")` elsewhere.
pub const HELP: &str = "Command::new(\"curl\") is not called here";
