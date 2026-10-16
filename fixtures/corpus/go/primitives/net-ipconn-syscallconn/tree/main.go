package main

import pkg "net"

func probe() {
    var v pkg.IPConn
    v.SyscallConn()
}
