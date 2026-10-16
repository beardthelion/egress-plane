package main

import pkg "golang.org/x/sys/unix"

func probe() {
    pkg.Listen()
}
