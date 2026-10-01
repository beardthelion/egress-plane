import subprocess


def probe(target):
    return subprocess._fork_exec(target)
