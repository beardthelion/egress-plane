from socketserver import selectors, threading

def probe():
    return (
        selectors,
        threading,
    )
