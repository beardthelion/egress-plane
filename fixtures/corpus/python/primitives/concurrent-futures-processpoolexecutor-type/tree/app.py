import concurrent.futures


def probe():
    return concurrent.futures.ProcessPoolExecutor()
