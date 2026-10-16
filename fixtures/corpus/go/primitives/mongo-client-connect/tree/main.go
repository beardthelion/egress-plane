package main

import pkg "go.mongodb.org/mongo-driver/mongo"

func probe() {
    var v pkg.Client
    v.Connect()
}
