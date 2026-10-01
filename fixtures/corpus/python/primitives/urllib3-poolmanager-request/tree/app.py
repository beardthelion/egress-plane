import urllib3


def probe(target):
    s = urllib3.PoolManager()
    return s.request(None, target)
