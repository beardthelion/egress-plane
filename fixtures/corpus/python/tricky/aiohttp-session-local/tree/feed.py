import aiohttp


async def load():
    session = aiohttp.ClientSession()
    resp = await session.get("https://api.example.com/feed")
    await session.close()
    return resp
