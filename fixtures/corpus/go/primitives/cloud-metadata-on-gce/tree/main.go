package main

import pkg "cloud.google.com/go/compute/metadata"

func probe() {
    pkg.OnGCE()
}
