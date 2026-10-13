package main

import "net/http"

func main() {
	c := new(http.Client)
	c.Get("https://api.example.com/v1/ping")
}
