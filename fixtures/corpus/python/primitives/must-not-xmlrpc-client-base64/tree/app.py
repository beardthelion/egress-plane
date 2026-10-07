from xmlrpc.client import base64, errno, expat, gzip, time

def probe():
    return (
        base64,
        errno,
        expat,
        gzip,
        time,
    )
