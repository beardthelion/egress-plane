import os


def probe():
    @os.system
    def helper(x):
        return x

    return helper
