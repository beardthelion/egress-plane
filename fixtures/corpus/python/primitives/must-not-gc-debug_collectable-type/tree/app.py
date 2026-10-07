from gc import DEBUG_COLLECTABLE, DEBUG_LEAK, DEBUG_SAVEALL, DEBUG_STATS, DEBUG_UNCOLLECTABLE, callbacks, collect, disable, enable, freeze, get_count, get_debug, get_freeze_count, get_stats, get_threshold, is_finalized, is_tracked, isenabled, set_debug, set_threshold, unfreeze

def probe():
    return (
        DEBUG_COLLECTABLE,
        DEBUG_LEAK,
        DEBUG_SAVEALL,
        DEBUG_STATS,
        DEBUG_UNCOLLECTABLE,
        callbacks,
        collect,
        disable,
        enable,
        freeze,
        get_count,
        get_debug,
        get_freeze_count,
        get_stats,
        get_threshold,
        is_finalized,
        is_tracked,
        isenabled,
        set_debug,
        set_threshold,
        unfreeze,
    )
