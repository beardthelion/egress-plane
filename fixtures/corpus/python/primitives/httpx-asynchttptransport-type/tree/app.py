import httpx


def probe():
    return httpx.AsyncHTTPTransport()
