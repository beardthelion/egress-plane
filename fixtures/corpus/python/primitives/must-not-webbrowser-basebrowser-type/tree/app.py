from webbrowser import BaseBrowser, Error, _browsers, _lock, _os_preferred_browser, _tryorder, parse_args, register

def probe():
    return (
        BaseBrowser,
        Error,
        _browsers,
        _lock,
        _os_preferred_browser,
        _tryorder,
        parse_args,
        register,
    )
