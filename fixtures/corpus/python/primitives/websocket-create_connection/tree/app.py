import websocket


def probe(target):
    return websocket.create_connection(target)
