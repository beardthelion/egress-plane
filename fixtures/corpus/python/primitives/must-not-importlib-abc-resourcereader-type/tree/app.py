from importlib.abc import ResourceReader, Traversable, TraversableResources, _register

def probe():
    return (
        ResourceReader,
        Traversable,
        TraversableResources,
        _register,
    )
