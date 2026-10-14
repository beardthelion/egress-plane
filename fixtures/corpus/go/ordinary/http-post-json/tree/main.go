package main

import (
	"net/http"
	"strings"
)

func main() {
	resp, err := http.Post("https://api.example.com/v1/items", "application/json", strings.NewReader("{}"))
	_ = err
	_ = resp
}
