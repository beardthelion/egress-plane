import redis


def probe(target):
    return redis.Redis(target)
