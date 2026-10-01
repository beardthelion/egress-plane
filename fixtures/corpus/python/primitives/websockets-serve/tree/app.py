import websockets


def probe():
    return websockets.serve(None, "api.example.test", 443)
