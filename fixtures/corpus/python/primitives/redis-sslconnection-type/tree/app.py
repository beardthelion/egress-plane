import redis


def probe(target):
    return redis.SSLConnection(target)
