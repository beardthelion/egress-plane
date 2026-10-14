package main

import h "net/http"

func main() {
	h.Get("https://api.example.com/v1/ping")
}
