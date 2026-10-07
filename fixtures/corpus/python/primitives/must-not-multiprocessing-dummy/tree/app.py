from multiprocessing import dummy, heap, queues, shared_memory, sharedctypes, synchronize

def probe():
    return (
        dummy,
        heap,
        queues,
        shared_memory,
        sharedctypes,
        synchronize,
    )
