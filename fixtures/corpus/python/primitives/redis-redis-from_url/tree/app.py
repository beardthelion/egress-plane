import redis


def probe(target):
    return redis.Redis.from_url(target)
