import ftplib


def probe(target):
    return ftplib.FTP_TLS(target)
