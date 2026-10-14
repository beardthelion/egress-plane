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
	// The same members as type-qualified selectors, naming the entries.
	_ = reflect.MethodByName
	_ = reflect.Value.MethodByName
	_ = reflect.Value.FieldByName
	_ = reflect.Value.Field
	_ = reflect.Value.Method
	_ = reflect.Value.FieldByIndex
	_ = reflect.Value.FieldByNameFunc
}
