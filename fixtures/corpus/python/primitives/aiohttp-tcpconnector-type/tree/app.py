import aiohttp


def probe():
    return aiohttp.TCPConnector()
