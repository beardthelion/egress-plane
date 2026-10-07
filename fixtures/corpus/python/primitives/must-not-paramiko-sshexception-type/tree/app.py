from paramiko import AuthenticationException, BadHostKeyException, PasswordRequiredException, SSHException

def probe():
    return (
        SSHException,
        AuthenticationException,
        BadHostKeyException,
        PasswordRequiredException,
    )
