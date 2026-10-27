package main

import "net/http"

type client struct{}

func probe() any {
	return &client{}
}
