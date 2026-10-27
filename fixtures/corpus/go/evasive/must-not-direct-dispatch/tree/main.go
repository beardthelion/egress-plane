package main

import "reflect"

type Greeter interface{ Get() }

func probe(name string, x any) {
	x.(Greeter).Get()
}
