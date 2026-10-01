import aiohttp


def probe(target):
    return aiohttp.request(None, target)
