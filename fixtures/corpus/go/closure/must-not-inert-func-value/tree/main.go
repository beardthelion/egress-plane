package main

import (
	"net/http"
	"strings"
)

func probe() {
	f := strings.ToUpper
	f("https://x.example/")
}
