import paramiko


def probe(target):
    s = paramiko.SSHClient()
    return s.connect(target)
