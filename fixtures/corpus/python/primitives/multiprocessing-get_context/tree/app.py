import multiprocessing


def probe():
    return multiprocessing.get_context()
