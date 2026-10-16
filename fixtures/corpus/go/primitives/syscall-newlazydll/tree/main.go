package main

import pkg "syscall"

func probe() {
    pkg.NewLazyDLL("x.so")
}
