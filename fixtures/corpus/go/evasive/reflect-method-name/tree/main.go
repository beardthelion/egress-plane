package main

import "reflect"

type Greeter interface{ Get() }

func probe(name string, x any) {
	reflect.ValueOf(x).MethodByName(name).Call(nil)
}
