import websocket


def probe(target):
    s = websocket.WebSocket()
    return s.connect(target)
