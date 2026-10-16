package main

import pkg "syscall"

func probe() {
    var v pkg.LazyProc
    v.Find()
}
