import nntplib


def probe(target):
    return nntplib.NNTP_SSL(target)
