#[path = "platform/linux_net.rs"]
mod net;

fn main() {
    net::connect();
}
