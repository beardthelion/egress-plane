package main

import (
	"net/http"
	"net/url"
)

func main() {
	r, err := http.PostForm("https://api.example.com/v1/form", url.Values{})
	_ = err
	_ = r
}
