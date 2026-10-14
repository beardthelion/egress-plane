package main

import "net/http"

func pick[T any](x T) T { return x }

func main() {
	c := pick[http.Client](http.Client{})
	c.Get("https://api.example.com/v1/ping")
}
