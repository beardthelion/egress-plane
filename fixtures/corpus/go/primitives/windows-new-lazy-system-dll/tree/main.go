package main

import pkg "golang.org/x/sys/windows"

func probe() {
    pkg.NewLazySystemDLL("x.so")
}
