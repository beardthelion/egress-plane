from mailcap import UnsafeMailcapInput, _DEPRECATION_MSG, _find_unsafe, _readmailcapfile, findparam, getcaps, lineno_sort_key, listmailcapfiles, lookup, parsefield, parseline, readmailcapfile, show, subst

def probe():
    return (
        UnsafeMailcapInput,
        _DEPRECATION_MSG,
        _find_unsafe,
        _readmailcapfile,
        findparam,
        getcaps,
        lineno_sort_key,
        listmailcapfiles,
        lookup,
        parsefield,
        parseline,
        readmailcapfile,
        show,
        subst,
    )
