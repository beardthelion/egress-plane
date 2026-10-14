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
	// The type member sets stay inert; the selector forms name them.
	_ = expvar.Float.Add
	_ = expvar.Int.Add
	_ = expvar.Map.Init
	_ = expvar.String.Set
	_ = expvar.Func.String
}
