from importlib.machinery import BYTECODE_SUFFIXES, DEBUG_BYTECODE_SUFFIXES, EXTENSION_SUFFIXES, ModuleSpec, OPTIMIZED_BYTECODE_SUFFIXES, SOURCE_SUFFIXES, all_suffixes

def probe():
    return (
        BYTECODE_SUFFIXES,
        DEBUG_BYTECODE_SUFFIXES,
        EXTENSION_SUFFIXES,
        ModuleSpec,
        OPTIMIZED_BYTECODE_SUFFIXES,
        SOURCE_SUFFIXES,
        all_suffixes,
    )
