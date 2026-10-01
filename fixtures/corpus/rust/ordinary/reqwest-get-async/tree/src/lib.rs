pub async fn fetch() -> Result<String, reqwest::Error> {
    reqwest::get("https://api.example.com/x").await?.text().await
}
