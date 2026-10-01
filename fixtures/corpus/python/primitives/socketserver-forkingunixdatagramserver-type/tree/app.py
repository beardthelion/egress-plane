import socketserver


def probe(target):
    return socketserver.ForkingUnixDatagramServer(target)
