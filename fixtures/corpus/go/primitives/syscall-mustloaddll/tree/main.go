package main

import pkg "syscall"

func probe() {
    pkg.MustLoadDLL("x.so")
}
