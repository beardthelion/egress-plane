from websockets import Headers, datastructures, frames, http11, typing

def probe():
    return (
        Headers,
        datastructures,
        frames,
        http11,
        typing,
    )
