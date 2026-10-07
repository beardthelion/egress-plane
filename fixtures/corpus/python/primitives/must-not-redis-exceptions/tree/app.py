from redis import AuthenticationError, ConnectionError, DataError, RedisError, ResponseError, TimeoutError, WatchError, exceptions

def probe():
    return (
        exceptions,
        RedisError,
        ConnectionError,
        TimeoutError,
        ResponseError,
        AuthenticationError,
        DataError,
        WatchError,
    )
