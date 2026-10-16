package main

import pkg "syscall"

func probe() {
    var v pkg.Proc
    v.Call()
}
