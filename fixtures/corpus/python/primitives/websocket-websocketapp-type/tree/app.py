import websocket


def probe(target):
    return websocket.WebSocketApp(target)
