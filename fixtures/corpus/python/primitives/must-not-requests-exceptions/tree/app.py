from requests import ConnectTimeout, ConnectionError, HTTPError, JSONDecodeError, ReadTimeout, RequestException, Timeout, TooManyRedirects, URLRequired, exceptions

def probe():
    return (
        exceptions,
        RequestException,
        HTTPError,
        ConnectionError,
        Timeout,
        ConnectTimeout,
        ReadTimeout,
        TooManyRedirects,
        URLRequired,
        JSONDecodeError,
    )
