from requests import PreparedRequest, Request, Response, __version__, auth, codes, cookies, hooks, models, status_codes, structures

def probe():
    return (
        PreparedRequest,
        Request,
        Response,
        __version__,
        auth,
        codes,
        cookies,
        hooks,
        models,
        status_codes,
        structures,
    )
