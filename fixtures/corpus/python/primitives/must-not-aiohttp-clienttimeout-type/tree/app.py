from aiohttp import BasicAuth, ClientResponse, ClientTimeout, CookieJar, FormData, TraceConfig, web

def probe():
    return (
        ClientTimeout,
        BasicAuth,
        FormData,
        ClientResponse,
        CookieJar,
        TraceConfig,
        web.Application,
        web.Response,
        web.json_response,
        web.Request,
        web.RouteTableDef,
        web.HTTPException,
    )
