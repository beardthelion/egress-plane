import functools
import os


def schedule(cmd):
    run = functools.partial(os.system, cmd)
    j = os.path.join
    return run, j
