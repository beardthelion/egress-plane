package main

import pkg "golang.org/x/sys/windows"

func probe() {
    pkg.MustLoadDLL("x.so")
}
