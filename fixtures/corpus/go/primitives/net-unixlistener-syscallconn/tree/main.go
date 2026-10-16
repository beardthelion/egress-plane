package main

import pkg "net"

func probe() {
    var v pkg.UnixListener
    v.SyscallConn()
}
