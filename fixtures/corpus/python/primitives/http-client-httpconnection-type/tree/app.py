import http.client


def probe(target):
    return http.client.HTTPConnection(target)
