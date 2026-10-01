import socket


def probe():
    return socket.fromfd()
