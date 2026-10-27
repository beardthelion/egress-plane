# Supply-chain demo: event-stream / flatmap-stream (2018)

`flatmap-stream` was the package smuggled into `event-stream`'s
dependency tree in 2018; its npm `0.1.1` tarball carried a payload that
probed the environment, read a wallet file, and exfiltrated it over
https. The malicious version was yanked; the files under
`app/node_modules/flatmap-stream/` are a reconstruction that follows
the published incident analysis and fire on no real host.

Run it:

```sh
egress-plane scan examples/supply-chain-demo/app
# state: complete, and "unscanned dependency: flatmap-stream"

egress-plane scan examples/supply-chain-demo/app \
  --deps examples/supply-chain-demo/app/node_modules
# the dependency pass opens the package and reports:
#   lib/hidden.js: https.request -> exfil.invalid POST (the exfil route)
#   index.min.js: new Function("require", payload)  dynamic-code
#   index.min.js: require                          dynamic-import
#   imports unscanned: ps-tree
```

The first scan says only that the dep is unscanned. The `--deps` pass
opens installed package source and finds the egress route plus the
eval-and-require loader that hid it, the shape of the actual incident.
