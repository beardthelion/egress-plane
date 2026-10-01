import logging.handlers


def probe(target):
    return logging.handlers.HTTPHandler(target)
