from requests import PreparedRequest, Request, Response, __version__, auth, codes, cookies, hooks, models, status_codes, structures

def probe():
    return (
        codes,
        status_codes,
        structures,
        auth,
        cookies,
        models,
        hooks,
        Request,
        PreparedRequest,
        Response,
        __version__,
    )
