import socketserver


def probe():
    return socketserver.ThreadingTCPServer(("api.example.test", 443))
