from websockets import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK, InvalidHandshake, InvalidURI, WebSocketException, exceptions

def probe():
    return (
        ConnectionClosed,
        ConnectionClosedError,
        ConnectionClosedOK,
        InvalidHandshake,
        InvalidURI,
        WebSocketException,
        exceptions,
    )
