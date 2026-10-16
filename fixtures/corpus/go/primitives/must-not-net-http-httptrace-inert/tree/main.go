package main

import pkg "net/http/httptrace"

func main() {
    _ = pkg.ContextClientTrace
    _ = pkg.DNSDoneInfo
    _ = pkg.DNSStartInfo
    _ = pkg.GotConnInfo
    _ = pkg.WithClientTrace
    _ = pkg.WroteRequestInfo
}
