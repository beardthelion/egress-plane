import syslog


def probe():
    return syslog.openlog()
