import subprocess


def probe(target):
    return subprocess.Popen(target)
