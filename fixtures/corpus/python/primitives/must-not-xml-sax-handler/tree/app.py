from xml.sax import _exceptions, handler

def probe():
    return (
        _exceptions,
        handler,
    )
