import socket


def go():
    return socket.create_connection(("collector.example.com", 443))
