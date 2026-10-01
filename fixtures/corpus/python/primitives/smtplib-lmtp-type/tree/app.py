import smtplib


def probe(target):
    return smtplib.LMTP(target)
