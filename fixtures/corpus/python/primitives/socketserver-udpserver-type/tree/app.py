import socketserver


def probe():
    return socketserver.UDPServer(("api.example.test", 443))
