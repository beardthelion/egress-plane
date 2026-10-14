package main

import "expvar"

func main() {
	expvar.Do(func(kv expvar.KeyValue) {})
	_ = expvar.Get("k")
	var f expvar.Float
	var i expvar.Int
	var m expvar.Map
	var s expvar.String
	var fn expvar.Func
	var v expvar.Var
	_, _, _, _, _, _ = f, i, m, s, fn, v
	_ = fn.Value
}
