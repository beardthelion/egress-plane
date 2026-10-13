package main

import "net/http"

const endpoint = "https://api.example.com/v1/ping"

func main() {
	http.Get(endpoint)
}
