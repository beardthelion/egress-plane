import poplib


def probe(target):
    return poplib.POP3(target)
