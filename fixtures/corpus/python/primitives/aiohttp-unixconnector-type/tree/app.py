import aiohttp


def probe(target):
    return aiohttp.UnixConnector(target)
