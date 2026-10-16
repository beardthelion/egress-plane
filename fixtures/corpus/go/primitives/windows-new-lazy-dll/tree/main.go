package main

import pkg "golang.org/x/sys/windows"

func probe() {
    pkg.NewLazyDLL("x.so")
}
