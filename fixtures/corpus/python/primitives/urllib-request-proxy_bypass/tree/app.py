import urllib.request


def probe():
    return urllib.request.proxy_bypass()
