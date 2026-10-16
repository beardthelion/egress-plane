package main

import pkg "golang.org/x/net/proxy"

func probe() {
    pkg.FromEnvironment()
}
