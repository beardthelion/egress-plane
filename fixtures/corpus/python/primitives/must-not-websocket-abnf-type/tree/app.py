from websocket import ABNF, enableTrace, getdefaulttimeout, setdefaulttimeout

def probe():
    return (
        ABNF,
        enableTrace,
        getdefaulttimeout,
        setdefaulttimeout,
    )
