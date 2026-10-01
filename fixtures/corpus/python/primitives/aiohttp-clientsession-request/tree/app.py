import aiohttp


def probe(target):
    s = aiohttp.ClientSession()
    return s.request(None, target)
