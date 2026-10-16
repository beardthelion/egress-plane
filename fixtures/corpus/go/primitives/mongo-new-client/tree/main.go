package main

import pkg "go.mongodb.org/mongo-driver/mongo"

func probe() {
    pkg.NewClient()
}
