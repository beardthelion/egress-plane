import redis


def probe(target):
    return redis.from_url(target)
