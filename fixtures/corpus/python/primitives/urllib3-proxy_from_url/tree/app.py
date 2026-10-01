import urllib3


def probe(target):
    return urllib3.proxy_from_url(target)
