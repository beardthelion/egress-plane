from pkgutil import ModuleInfo, ModuleType, _NAME_PATTERN, _iter_file_finder_modules, extend_path, iter_importer_modules, iter_modules, iter_zipimport_modules, namedtuple, simplegeneric

def probe():
    return (
        ModuleInfo,
        ModuleType,
        _NAME_PATTERN,
        _iter_file_finder_modules,
        extend_path,
        iter_importer_modules,
        iter_modules,
        iter_zipimport_modules,
        namedtuple,
        simplegeneric,
    )
