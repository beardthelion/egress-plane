import uuid


def probe():
    return uuid._arp_getnode()
