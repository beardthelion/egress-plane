from ctypes.util import re, shutil, tempfile

def probe():
    return (
        re,
        shutil,
        tempfile,
    )
