import nntplib


def probe(target):
    return nntplib.NNTP(target)
