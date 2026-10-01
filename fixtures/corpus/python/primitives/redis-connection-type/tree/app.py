import redis


def probe(target):
    return redis.Connection(target)
