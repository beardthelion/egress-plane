import multiprocessing


def probe(target):
    return multiprocessing.set_executable(target)
