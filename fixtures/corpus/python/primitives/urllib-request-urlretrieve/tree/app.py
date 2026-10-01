import urllib.request


def probe(target):
    return urllib.request.urlretrieve(target)
