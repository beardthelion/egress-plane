import uuid


def probe():
    return uuid._netstat_getnode()
