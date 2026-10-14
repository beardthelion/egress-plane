from requests import ConnectTimeout, ConnectionError, HTTPError, JSONDecodeError, ReadTimeout, RequestException, Timeout, TooManyRedirects, URLRequired, exceptions

def probe():
    return (
        ConnectTimeout,
        ConnectionError,
        HTTPError,
        JSONDecodeError,
        ReadTimeout,
        RequestException,
        Timeout,
        TooManyRedirects,
        URLRequired,
        exceptions,
    )
