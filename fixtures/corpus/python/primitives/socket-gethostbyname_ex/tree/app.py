import socket


def probe(target):
    return socket.gethostbyname_ex(target)
