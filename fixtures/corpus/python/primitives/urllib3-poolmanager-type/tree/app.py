import urllib3


def probe():
    return urllib3.PoolManager()
