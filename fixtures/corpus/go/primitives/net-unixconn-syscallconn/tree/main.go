package main

import pkg "net"

func probe() {
    var v pkg.UnixConn
    v.SyscallConn()
}
