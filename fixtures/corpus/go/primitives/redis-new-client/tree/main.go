package main

import "github.com/redis/go-redis/v9"

func main() {
	c := redis.NewClient(nil)
	_ = c
}
