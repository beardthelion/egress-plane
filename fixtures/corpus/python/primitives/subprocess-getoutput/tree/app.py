import subprocess


def probe(target):
    return subprocess.getoutput(target)
