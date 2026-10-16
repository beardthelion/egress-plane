package main

import pkg "net/http/pprof"

func probe() {
    pkg.Handler()
}
