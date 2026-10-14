from redis import AuthenticationError, ConnectionError, DataError, RedisError, ResponseError, TimeoutError, WatchError, exceptions

def probe():
    return (
        AuthenticationError,
        ConnectionError,
        DataError,
        RedisError,
        ResponseError,
        TimeoutError,
        WatchError,
        exceptions,
    )
