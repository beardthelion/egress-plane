from importlib.util import MAGIC_NUMBER, _RAW_MAGIC_NUMBER, _incompatible_extension_module_restrictions, _resolve_name, cache_from_source, contextmanager, decode_source, module_for_loader, resolve_name, set_loader, set_package, source_from_cache, source_hash

def probe():
    return (
        MAGIC_NUMBER,
        _RAW_MAGIC_NUMBER,
        _incompatible_extension_module_restrictions,
        _resolve_name,
        cache_from_source,
        contextmanager,
        decode_source,
        module_for_loader,
        resolve_name,
        set_loader,
        set_package,
        source_from_cache,
        source_hash,
    )
