import httpx


async def load():
    client = httpx.AsyncClient()
    return await client.get("https://api.example.com/async")
