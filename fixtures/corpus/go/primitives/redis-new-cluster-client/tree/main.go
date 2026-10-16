package main

import pkg "github.com/redis/go-redis/v9"

func probe() {
    pkg.NewClusterClient()
}
