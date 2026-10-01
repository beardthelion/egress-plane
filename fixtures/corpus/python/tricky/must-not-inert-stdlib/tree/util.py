import collections
import json
import math
import re


def summarize(text):
    words = re.findall(r"\w+", text)
    counts = collections.Counter(words)
    return json.dumps({"top": counts.most_common(3), "root": math.sqrt(len(words))})
