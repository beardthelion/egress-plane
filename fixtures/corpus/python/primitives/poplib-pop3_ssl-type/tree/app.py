import poplib


def probe(target):
    return poplib.POP3_SSL(target)
