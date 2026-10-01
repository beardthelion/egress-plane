import urllib.request


def probe():
    return urllib.request._safe_gethostbyname()
