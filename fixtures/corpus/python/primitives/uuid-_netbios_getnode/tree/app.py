import uuid


def probe():
    return uuid._netbios_getnode()
