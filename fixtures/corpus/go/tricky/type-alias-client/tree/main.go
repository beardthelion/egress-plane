package main

import "net/http"

type Client = http.Client

func main() {
	var c Client
	c.Get("https://api.example.com/v1/ping")
}
