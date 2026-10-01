import socket


def probe(target):
    return socket.gethostbyaddr(target)
