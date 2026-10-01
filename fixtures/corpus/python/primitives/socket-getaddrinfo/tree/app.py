import socket


def probe():
    return socket.getaddrinfo("api.example.test", 443)
