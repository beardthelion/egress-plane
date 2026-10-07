from webbrowser import shlex, shutil, threading

def probe():
    return (
        shlex,
        shutil,
        threading,
    )
