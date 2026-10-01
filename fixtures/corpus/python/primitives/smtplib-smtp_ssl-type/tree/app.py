import smtplib


def probe(target):
    return smtplib.SMTP_SSL(target)
