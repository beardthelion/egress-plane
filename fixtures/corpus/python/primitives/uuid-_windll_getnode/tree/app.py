import uuid


def probe():
    return uuid._windll_getnode()
