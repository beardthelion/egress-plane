import paramiko


def probe():
    return paramiko.SSHClient()
