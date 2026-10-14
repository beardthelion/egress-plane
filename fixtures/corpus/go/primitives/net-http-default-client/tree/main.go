package main

import "net/http"

func main() {
	c := http.DefaultClient
	c.Get("https://api.example.com/v1/ping")
	http.DefaultClient.Get("https://api.example.com/v1/health")
}
