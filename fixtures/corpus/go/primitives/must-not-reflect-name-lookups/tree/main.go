package main

import "reflect"

func main() {
	v := reflect.ValueOf(0)
	_ = v.Field(0)
	_ = v.FieldByIndex(nil)
	_ = v.FieldByName("Name")
	_ = v.FieldByNameFunc(func(string) bool { return false })
	_ = v.Method(0)
	_ = v.MethodByName("Close")
}
