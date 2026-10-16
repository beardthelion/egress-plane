package main

import pkg "syscall"

func probe() {
    var v pkg.DLL
    v.MustFindProc()
}
