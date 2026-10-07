from httpx import ConnectError, ConnectTimeout, HTTPError, HTTPStatusError, InvalidURL, ReadTimeout, RequestError, TimeoutException, TransportError

def probe():
    return (
        HTTPError,
        RequestError,
        HTTPStatusError,
        TransportError,
        TimeoutException,
        ConnectError,
        ConnectTimeout,
        ReadTimeout,
        InvalidURL,
    )
