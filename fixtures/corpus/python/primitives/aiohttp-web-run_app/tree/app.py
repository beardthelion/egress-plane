import aiohttp


def probe():
    return aiohttp.web.run_app()
