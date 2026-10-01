import socket


def probe():
    s = socket.socket()
    return s.connect_ex(("api.example.test", 443))
