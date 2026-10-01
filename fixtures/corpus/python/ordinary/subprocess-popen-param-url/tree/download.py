import subprocess


def download(url):
    return subprocess.Popen(["wget", "-q", url])
