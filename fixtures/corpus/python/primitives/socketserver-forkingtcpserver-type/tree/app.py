import socketserver


def probe():
    return socketserver.ForkingTCPServer(("api.example.test", 443))
