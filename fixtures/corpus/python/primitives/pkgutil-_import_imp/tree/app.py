import pkgutil

def probe():
    return pkgutil._import_imp
