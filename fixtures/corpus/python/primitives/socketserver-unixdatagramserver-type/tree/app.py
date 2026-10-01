import socketserver


def probe(target):
    return socketserver.UnixDatagramServer(target)
