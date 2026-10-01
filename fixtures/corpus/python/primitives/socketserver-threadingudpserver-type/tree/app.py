import socketserver


def probe():
    return socketserver.ThreadingUDPServer(("api.example.test", 443))
