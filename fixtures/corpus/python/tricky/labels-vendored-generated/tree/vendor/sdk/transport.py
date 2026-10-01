import socket


def connect():
    return socket.create_connection(("sdk.example.com", 443))
