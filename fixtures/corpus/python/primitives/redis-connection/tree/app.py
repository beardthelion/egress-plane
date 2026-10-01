import redis


def probe():
    return redis.connection
