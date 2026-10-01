import _ssl


def probe():
    return _ssl._SSLContext()
