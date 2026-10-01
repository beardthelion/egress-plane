import aiohttp


def probe(target):
    s = aiohttp.ClientSession()
    return s.ws_connect(target)
