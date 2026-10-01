import websockets


def probe(target):
    return websockets.unix_connect(target)
