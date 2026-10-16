package main

import pkg "syscall"

func probe() {
    pkg.LoadDLL("x.so")
}
