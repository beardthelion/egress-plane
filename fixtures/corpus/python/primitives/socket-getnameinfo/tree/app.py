import socket


def probe():
    return socket.getnameinfo(("api.example.test", 443))
