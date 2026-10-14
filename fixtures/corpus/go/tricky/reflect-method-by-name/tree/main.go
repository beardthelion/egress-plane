package main

import (
	"net/http"
	"reflect"
)

var client http.Client

func access(name string) {
	reflect.ValueOf(client).MethodByName(name)
}

func unknown(c any, name string) {
	reflect.ValueOf(c).MethodByName(name)
}

func main() {}
