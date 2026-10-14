from pycurl import CurlShare, global_cleanup, global_init, version, version_info

def probe():
    return (
        CurlShare,
        global_cleanup,
        global_init,
        version,
        version_info,
    )
