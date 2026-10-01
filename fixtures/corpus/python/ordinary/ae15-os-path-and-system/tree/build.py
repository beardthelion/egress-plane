import os


def build_and_run(a, b, cmd):
    target = os.path.join(a, b)
    os.system(cmd)
    return target
