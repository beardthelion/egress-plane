import aiohttp


def probe(target):
    return aiohttp.web.UnixSite(None, target)
