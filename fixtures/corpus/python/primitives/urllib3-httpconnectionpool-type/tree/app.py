import urllib3


def probe(target):
    return urllib3.HTTPConnectionPool(target)
