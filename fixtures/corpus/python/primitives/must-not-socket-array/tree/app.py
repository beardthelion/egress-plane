from socket import array, errno, io, selectors

def probe():
    return (
        array,
        errno,
        io,
        selectors,
    )
