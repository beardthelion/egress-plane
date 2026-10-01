import imaplib


def probe(target):
    return imaplib.IMAP4_stream(target)
