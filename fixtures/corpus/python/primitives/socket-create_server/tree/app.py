import socket


def probe():
    return socket.create_server(("api.example.test", 443))
