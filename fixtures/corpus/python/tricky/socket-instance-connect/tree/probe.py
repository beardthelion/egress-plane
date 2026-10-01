import socket


def probe():
    s = socket.socket()
    s.connect(("api.example.com", 443))
    s.close()
