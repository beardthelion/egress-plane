import websockets


def probe(target):
    return websockets.connect(target)
