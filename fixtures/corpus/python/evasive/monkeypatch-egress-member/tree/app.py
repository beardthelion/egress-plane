import json
import os


def probe(hook):
    os.system = hook
