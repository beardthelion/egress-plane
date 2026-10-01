import socket


def probe(target):
    return socket.getfqdn(target)
