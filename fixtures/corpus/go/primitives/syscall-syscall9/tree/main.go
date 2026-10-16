package main

import pkg "syscall"

func probe() {
    pkg.Syscall9()
}
