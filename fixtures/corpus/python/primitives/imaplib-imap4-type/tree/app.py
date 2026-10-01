import imaplib


def probe(target):
    return imaplib.IMAP4(target)
