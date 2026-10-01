import socketserver


def probe(target):
    return socketserver.UnixStreamServer(target)
