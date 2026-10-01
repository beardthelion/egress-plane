import socket


def probe():
    s = socket.socket()
    return s.sendto(None, ("api.example.test", 443))
