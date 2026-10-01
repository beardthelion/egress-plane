import redis


def probe(target):
    return redis.StrictRedis(target)
