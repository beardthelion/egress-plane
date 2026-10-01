import asyncio


async def open_stream():
    reader, writer = await asyncio.open_connection("api.example.com", 8443)
    writer.close()
    return reader
