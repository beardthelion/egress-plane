import ssl


def probe():
    return ssl.socket()
