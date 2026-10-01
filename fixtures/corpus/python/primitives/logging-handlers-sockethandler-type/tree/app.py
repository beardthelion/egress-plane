import logging.handlers


def probe():
    return logging.handlers.SocketHandler("api.example.test", 443)
