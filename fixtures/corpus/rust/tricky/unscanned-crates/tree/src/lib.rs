pub fn encode(n: u32) -> String {
    serde_json::to_string(&n).unwrap()
}

pub fn roll() -> u32 {
    rand::random::<u32>() % 6
}
