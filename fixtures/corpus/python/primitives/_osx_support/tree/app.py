import _osx_support


def probe():
    return _osx_support._get_system_version()
