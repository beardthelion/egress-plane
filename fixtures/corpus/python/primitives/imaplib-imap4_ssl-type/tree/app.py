import imaplib


def probe(target):
    return imaplib.IMAP4_SSL(target)
