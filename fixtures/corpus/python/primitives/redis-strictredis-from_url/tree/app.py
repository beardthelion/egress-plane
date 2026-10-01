import redis


def probe(target):
    return redis.StrictRedis.from_url(target)
