package main

import "net/http"

func main() {
	err := http.ListenAndServe("0.0.0.0:8080", nil)
	_ = err
}
