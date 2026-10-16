package main

import pkg "net"

func probe() {
    var v pkg.TCPConn
    v.SyscallConn()
}
