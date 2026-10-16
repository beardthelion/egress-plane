package main

import pkg "syscall"

func probe() {
    var v pkg.LazyDLL
    v.Load("x.so")
}
