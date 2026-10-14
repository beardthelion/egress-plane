package main

import "reflect"

func main() {
	var v reflect.Value
	out := v.Call(nil)
	_ = out
}
