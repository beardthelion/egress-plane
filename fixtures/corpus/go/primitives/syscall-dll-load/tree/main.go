package main

import pkg "syscall"

func probe() {
    var v pkg.DLL
    v.Load("x.so")
}
