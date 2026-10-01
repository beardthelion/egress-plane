import ftplib


def probe(target):
    return ftplib.FTP(target)
