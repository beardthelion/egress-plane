import logging.config


def probe():
    return logging.config.ThreadingTCPServer(("api.example.test", 443))
