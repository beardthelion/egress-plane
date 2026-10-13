package main

import "net/http"

func main() {
	c := http.Client{Timeout: 5}
	c.Get("https://api.example.com/v1/ping")
}
