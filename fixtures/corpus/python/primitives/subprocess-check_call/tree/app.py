import subprocess


def probe(target):
    return subprocess.check_call(target)
