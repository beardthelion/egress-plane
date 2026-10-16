package main

import pkg "go/build"

func probe() {
    var v pkg.Default
    v.Import()
}
