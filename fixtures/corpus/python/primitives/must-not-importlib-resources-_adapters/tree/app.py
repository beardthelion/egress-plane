from importlib.resources import _adapters, _common, _functional, _itertools, _legacy, readers, simple

def probe():
    return (
        _adapters,
        _common,
        _functional,
        _itertools,
        _legacy,
        readers,
        simple,
    )
