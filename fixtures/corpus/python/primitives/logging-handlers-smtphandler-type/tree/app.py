import logging.handlers


def probe():
    return logging.handlers.SMTPHandler(("api.example.test", 443))
