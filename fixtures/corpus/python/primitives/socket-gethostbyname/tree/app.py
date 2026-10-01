import socket


def probe(target):
    return socket.gethostbyname(target)
