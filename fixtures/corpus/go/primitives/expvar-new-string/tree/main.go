package main

import pkg "expvar"

func probe() {
    pkg.NewString()
}
