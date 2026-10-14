from paramiko import AuthenticationException, BadHostKeyException, PasswordRequiredException, SSHException

def probe():
    return (
        AuthenticationException,
        BadHostKeyException,
        PasswordRequiredException,
        SSHException,
    )
