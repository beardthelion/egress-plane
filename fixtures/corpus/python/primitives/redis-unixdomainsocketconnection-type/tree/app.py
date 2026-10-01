import redis


def probe(target):
    return redis.UnixDomainSocketConnection(target)
