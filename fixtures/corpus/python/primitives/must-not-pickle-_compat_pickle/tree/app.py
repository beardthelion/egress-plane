from pickle import _compat_pickle, codecs, io, re

def probe():
    return (
        _compat_pickle,
        codecs,
        io,
        re,
    )
