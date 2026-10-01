import redis


def probe(target):
    return redis.ConnectionPool.from_url(target)
