import urllib.request


def probe():
    return urllib.request.build_opener()
