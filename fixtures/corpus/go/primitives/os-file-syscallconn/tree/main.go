package main

import pkg "os"

func probe() {
    var v pkg.File
    v.SyscallConn()
}
