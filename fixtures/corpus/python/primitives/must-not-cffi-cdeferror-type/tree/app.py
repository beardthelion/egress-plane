from cffi import CDefError, FFIError, VerificationError, VerificationMissing

def probe():
    return (
        CDefError,
        FFIError,
        VerificationError,
        VerificationMissing,
    )
