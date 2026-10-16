package main

import pkg "syscall"

func probe() {
    pkg.SendmsgN()
}
