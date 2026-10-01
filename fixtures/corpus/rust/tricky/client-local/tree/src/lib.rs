pub async fn load() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    client.get("https://api.example.com/items").send().await?;
    Ok(())
}
