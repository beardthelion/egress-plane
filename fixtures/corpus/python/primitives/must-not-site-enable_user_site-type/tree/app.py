from site import ENABLE_USER_SITE, PREFIXES, USER_BASE, USER_SITE, _get_implementation, _get_path, _getuserbase, _init_pathinfo, _script, _trace, abs_paths, check_enableusersite, gethistoryfile, getsitepackages, getuserbase, getusersitepackages, makepath, removeduppaths, setcopyright, sethelper, setquit

def probe():
    return (
        ENABLE_USER_SITE,
        PREFIXES,
        USER_BASE,
        USER_SITE,
        _get_implementation,
        _get_path,
        _getuserbase,
        _init_pathinfo,
        _script,
        _trace,
        abs_paths,
        check_enableusersite,
        gethistoryfile,
        getsitepackages,
        getuserbase,
        getusersitepackages,
        makepath,
        removeduppaths,
        setcopyright,
        sethelper,
        setquit,
    )
