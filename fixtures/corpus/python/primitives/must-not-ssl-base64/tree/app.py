from ssl import base64, errno

def probe():
    return (
        base64,
        errno,
    )
