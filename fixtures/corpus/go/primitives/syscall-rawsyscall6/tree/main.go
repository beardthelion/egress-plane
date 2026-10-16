package main

import pkg "syscall"

func probe() {
    pkg.RawSyscall6()
}
