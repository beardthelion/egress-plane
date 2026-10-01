import socketserver


def probe():
    return socketserver.TCPServer(("api.example.test", 443))
