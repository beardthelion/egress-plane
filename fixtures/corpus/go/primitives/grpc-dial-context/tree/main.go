package main

import pkg "google.golang.org/grpc"

func probe() {
    pkg.DialContext("x", "x.example:443")
}
