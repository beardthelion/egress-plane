pub async fn connect() -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect("api.example.com:443").await
}
