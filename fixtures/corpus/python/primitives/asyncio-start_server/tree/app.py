import asyncio


def probe():
    return asyncio.start_server(None, "api.example.test", 443)
