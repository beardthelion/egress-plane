package main

import "net/http"

func main() {
	var c http.Client
	c.Get("https://api.example.com/v1/ping")
}
