import mailcap


def probe():
    return mailcap.findmatch()
