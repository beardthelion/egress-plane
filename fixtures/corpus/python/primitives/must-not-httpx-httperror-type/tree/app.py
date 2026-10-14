from httpx import ConnectError, ConnectTimeout, HTTPError, HTTPStatusError, InvalidURL, ReadTimeout, RequestError, TimeoutException, TransportError

def probe():
    return (
        ConnectError,
        ConnectTimeout,
        HTTPError,
        HTTPStatusError,
        InvalidURL,
        ReadTimeout,
        RequestError,
        TimeoutException,
        TransportError,
    )
