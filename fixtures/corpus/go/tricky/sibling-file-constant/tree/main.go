package main

import "net/http"

func fetch() {
	http.Get(base + "/v1")
}

func main() {}
