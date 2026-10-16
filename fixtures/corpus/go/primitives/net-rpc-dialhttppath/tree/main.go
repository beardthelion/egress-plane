package main

import pkg "net/rpc"

func probe() {
    pkg.DialHTTPPath("x", "x.example:443")
}
