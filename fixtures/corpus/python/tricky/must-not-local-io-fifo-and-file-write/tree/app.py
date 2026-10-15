import os


def probe(p, d):
    os.mkfifo(p)
    with open(p, "w") as f:
        f.write(d)
