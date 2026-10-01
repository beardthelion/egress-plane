import multiprocessing


def probe():
    return multiprocessing.popen_spawn_win32()
