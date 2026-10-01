import logging.handlers


def probe():
    return logging.handlers.SysLogHandler(("api.example.test", 443))
