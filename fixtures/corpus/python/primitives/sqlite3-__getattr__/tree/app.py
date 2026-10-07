import sqlite3

def probe():
    return sqlite3.__getattr__
