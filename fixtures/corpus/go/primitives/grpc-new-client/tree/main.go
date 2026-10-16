package main

import pkg "google.golang.org/grpc"

func probe() {
    pkg.NewClient("x.example:443")
}
