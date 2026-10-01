import paramiko


def probe():
    return paramiko.Transport(("api.example.test", 443))
