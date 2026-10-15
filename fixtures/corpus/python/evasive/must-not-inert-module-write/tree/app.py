import json
import os


def probe(hook):
    json.dumps = hook
