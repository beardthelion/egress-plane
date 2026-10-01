import paramiko


def probe(target):
    return paramiko.ProxyCommand(target)
