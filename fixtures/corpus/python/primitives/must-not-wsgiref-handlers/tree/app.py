from wsgiref import handlers, headers, types, util, validate

def probe():
    return (
        handlers,
        headers,
        types,
        util,
        validate,
    )
