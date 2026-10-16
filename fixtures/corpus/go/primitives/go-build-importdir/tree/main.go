package main

import pkg "go/build"

func probe() {
    pkg.ImportDir()
}
