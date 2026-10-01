import smtplib


def probe(target):
    return smtplib.SMTP(target)
