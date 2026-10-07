from importlib.metadata import _adapters, _collections, _functools, _itertools, _meta, _text, diagnose

def probe():
    return (
        _adapters,
        _collections,
        _functools,
        _itertools,
        _meta,
        _text,
        diagnose,
    )
