import uuid


def probe():
    return uuid._ifconfig_getnode()
