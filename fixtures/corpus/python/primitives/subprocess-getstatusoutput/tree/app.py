import subprocess


def probe(target):
    return subprocess.getstatusoutput(target)
