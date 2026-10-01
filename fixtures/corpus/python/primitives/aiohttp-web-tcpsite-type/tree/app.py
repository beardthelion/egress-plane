import aiohttp


def probe():
    return aiohttp.web.TCPSite(None, "api.example.test", 443)
