from logging import atexit, collections, io, re, threading, time, traceback, weakref

def probe():
    return (
        atexit,
        collections,
        io,
        re,
        threading,
        time,
        traceback,
        weakref,
    )
