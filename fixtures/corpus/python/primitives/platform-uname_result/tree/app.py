import platform


def probe():
    return platform.uname_result()
