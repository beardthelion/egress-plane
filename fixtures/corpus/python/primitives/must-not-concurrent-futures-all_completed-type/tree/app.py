from concurrent.futures import ALL_COMPLETED, BrokenExecutor, CancelledError, Executor, FIRST_COMPLETED, FIRST_EXCEPTION, Future, InvalidStateError, ThreadPoolExecutor, TimeoutError, __author__, as_completed, wait

def probe():
    return (
        ALL_COMPLETED,
        BrokenExecutor,
        CancelledError,
        Executor,
        FIRST_COMPLETED,
        FIRST_EXCEPTION,
        Future,
        InvalidStateError,
        ThreadPoolExecutor,
        TimeoutError,
        __author__,
        as_completed,
        wait,
    )
