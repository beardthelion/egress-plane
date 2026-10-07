from subprocess import contextlib, errno, fcntl, io, locale, select, selectors, signal, threading, time

def probe():
    return (
        contextlib,
        errno,
        fcntl,
        io,
        locale,
        select,
        selectors,
        signal,
        threading,
        time,
    )
