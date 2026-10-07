from pty import CHILD, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, _copy, _open_terminal, _read, close, fork, master_open, openpty, select, setraw, slave_open, tcgetattr, tcsetattr, waitpid

def probe():
    return (
        CHILD,
        STDERR_FILENO,
        STDIN_FILENO,
        STDOUT_FILENO,
        _copy,
        _open_terminal,
        _read,
        close,
        fork,
        master_open,
        openpty,
        select,
        setraw,
        slave_open,
        tcgetattr,
        tcsetattr,
        waitpid,
    )
