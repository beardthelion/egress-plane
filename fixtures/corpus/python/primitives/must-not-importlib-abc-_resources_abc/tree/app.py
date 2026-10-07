from importlib.abc import _resources_abc, abc

def probe():
    return (
        _resources_abc,
        abc,
    )
