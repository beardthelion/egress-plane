pub fn three() -> Result<(), reqwest::Error> {
    type C = reqwest::blocking::Client;
    let client = C::new();
    client.get("https://typealias-three.example.com/items").send()?;
    Ok(())
}
