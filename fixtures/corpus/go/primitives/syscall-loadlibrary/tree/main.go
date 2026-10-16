package main

import pkg "syscall"

func probe() {
    pkg.LoadLibrary("x.so")
}
