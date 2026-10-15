import os


def probe():
    def helper(cb=os.system):
        return cb

    return helper
