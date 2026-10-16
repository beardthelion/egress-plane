package main

import pkg "net"

func probe() {
    var v pkg.UDPConn
    v.SyscallConn()
}
