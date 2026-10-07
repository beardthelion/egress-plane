from aiohttp import ClientConnectionError, ClientConnectorError, ClientError, ClientPayloadError, ClientResponseError, ContentTypeError, ServerTimeoutError

def probe():
    return (
        ClientError,
        ClientResponseError,
        ClientConnectionError,
        ClientConnectorError,
        ContentTypeError,
        ServerTimeoutError,
        ClientPayloadError,
    )
