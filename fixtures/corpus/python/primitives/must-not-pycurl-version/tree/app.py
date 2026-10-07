from pycurl import CurlShare, global_cleanup, global_init, version, version_info

def probe():
    return (
        version,
        version_info,
        global_init,
        global_cleanup,
        CurlShare,
    )
