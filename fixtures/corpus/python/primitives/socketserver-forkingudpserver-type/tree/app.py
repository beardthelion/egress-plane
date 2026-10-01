import socketserver


def probe():
    return socketserver.ForkingUDPServer(("api.example.test", 443))
