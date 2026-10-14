from aiohttp import ClientConnectionError, ClientConnectorError, ClientError, ClientPayloadError, ClientResponseError, ContentTypeError, ServerTimeoutError

def probe():
    return (
        ClientConnectionError,
        ClientConnectorError,
        ClientError,
        ClientPayloadError,
        ClientResponseError,
        ContentTypeError,
        ServerTimeoutError,
    )
