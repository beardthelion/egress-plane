import socketserver


def probe(target):
    return socketserver.ThreadingUnixDatagramServer(target)
