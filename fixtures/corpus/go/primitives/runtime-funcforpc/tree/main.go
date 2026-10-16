package main

import pkg "runtime"

func probe() {
    pkg.FuncForPC()
}
