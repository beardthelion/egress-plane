package main

import pkg "reflect"

func main() {
    _ = pkg.MethodByName
    _ = pkg.Value.Field
    _ = pkg.Value.FieldByIndex
    _ = pkg.Value.FieldByName
    _ = pkg.Value.FieldByNameFunc
    _ = pkg.Value.Method
}
