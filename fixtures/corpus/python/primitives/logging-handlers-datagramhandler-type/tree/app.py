import logging.handlers


def probe():
    return logging.handlers.DatagramHandler("api.example.test", 443)
