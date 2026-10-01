import urllib.request


def probe():
    return urllib.request._proxy_bypass_macosx_sysconf()
