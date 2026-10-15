import requests


def w0(url):
    return requests.post(url)


def w1(url):
    return w0(url)


def w2(url):
    return w1(url)


def w3(url):
    return w2(url)


def w4(url):
    return w3(url)


def w5(url):
    return w4(url)


def w6(url):
    return w5(url)


def w7(url):
    return w6(url)


def w8(url):
    return w7(url)


def outside():
    return w8("https://x.invalid")
