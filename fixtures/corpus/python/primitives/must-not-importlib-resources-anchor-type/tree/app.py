from importlib.resources import Anchor, Package, Resource, ResourceReader

def probe():
    return (
        Anchor,
        Package,
        Resource,
        ResourceReader,
    )
