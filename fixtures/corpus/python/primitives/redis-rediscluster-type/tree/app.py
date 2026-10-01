import redis


def probe(target):
    return redis.RedisCluster(target)
