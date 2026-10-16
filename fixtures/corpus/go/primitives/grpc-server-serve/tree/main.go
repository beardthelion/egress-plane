package main

import pkg "google.golang.org/grpc"

func probe() {
    var v pkg.Server
    v.Serve()
}
