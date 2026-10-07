from xml.sax import _exceptions, handler

def probe():
    return (
        handler,
        _exceptions,
    )
