import websockets


def probe(target):
    return websockets.unix_serve(None, target)
