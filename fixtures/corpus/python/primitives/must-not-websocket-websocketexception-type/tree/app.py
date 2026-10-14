from websocket import WebSocketBadStatusException, WebSocketConnectionClosedException, WebSocketException, WebSocketTimeoutException

def probe():
    return (
        WebSocketBadStatusException,
        WebSocketConnectionClosedException,
        WebSocketException,
        WebSocketTimeoutException,
    )
