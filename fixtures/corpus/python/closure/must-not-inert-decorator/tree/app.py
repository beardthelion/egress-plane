import os


def probe():
    @len
    def helper(x):
        return x

    return helper
