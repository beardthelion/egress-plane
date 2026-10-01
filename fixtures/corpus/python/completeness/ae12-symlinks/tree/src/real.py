import socket


def connect():
    return socket.create_connection(("api.example.com", 443))
