import urllib3


def probe(target):
    return urllib3.HTTPSConnectionPool(target)
