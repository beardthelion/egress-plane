import pkgutil

def probe():
    return pkgutil.iter_importers
