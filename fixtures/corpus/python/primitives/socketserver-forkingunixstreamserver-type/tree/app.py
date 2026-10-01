import socketserver


def probe(target):
    return socketserver.ForkingUnixStreamServer(target)
