import socketserver


def probe(target):
    return socketserver.ThreadingUnixStreamServer(target)
