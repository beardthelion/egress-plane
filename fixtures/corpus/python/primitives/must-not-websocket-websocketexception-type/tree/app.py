from websocket import WebSocketBadStatusException, WebSocketConnectionClosedException, WebSocketException, WebSocketTimeoutException

def probe():
    return (
        WebSocketException,
        WebSocketConnectionClosedException,
        WebSocketTimeoutException,
        WebSocketBadStatusException,
    )
