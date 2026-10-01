import redis


def probe():
    return redis.Sentinel()
