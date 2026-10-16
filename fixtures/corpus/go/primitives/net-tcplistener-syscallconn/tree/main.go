package main

import pkg "net"

func probe() {
    var v pkg.TCPListener
    v.SyscallConn()
}
