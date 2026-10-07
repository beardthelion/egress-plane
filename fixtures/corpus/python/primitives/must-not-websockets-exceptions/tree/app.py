from websockets import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK, InvalidHandshake, InvalidURI, WebSocketException, exceptions

def probe():
    return (
        exceptions,
        ConnectionClosed,
        ConnectionClosedOK,
        ConnectionClosedError,
        InvalidURI,
        InvalidHandshake,
        WebSocketException,
    )
