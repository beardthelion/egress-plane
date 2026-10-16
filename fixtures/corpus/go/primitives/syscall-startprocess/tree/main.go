package main

import pkg "syscall"

func probe() {
    pkg.StartProcess("x")
}
