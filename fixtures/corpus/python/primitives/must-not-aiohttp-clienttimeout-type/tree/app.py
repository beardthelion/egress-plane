from aiohttp import BasicAuth, ClientResponse, ClientTimeout, CookieJar, FormData, TraceConfig, web

def probe():
    return (
        BasicAuth,
        ClientResponse,
        ClientTimeout,
        CookieJar,
        FormData,
        TraceConfig,
        web.Application,
        web.HTTPException,
        web.Request,
        web.Response,
        web.RouteTableDef,
        web.json_response,
    )
