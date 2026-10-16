package main

import pkg "net/http/httputil"

func main() {
    _ = pkg.BufferPool
    _ = pkg.ClientConn
    _ = pkg.ClientConn.Example
    _ = pkg.DumpReExample
    _ = pkg.ErrExample
    _ = pkg.NewChunkedReader
    _ = pkg.NewChunkedWriter
    _ = pkg.ProxyRequest
    _ = pkg.ProxyRequest.SetXForwarded
    _ = pkg.ServerConn
    _ = pkg.ServerConn.Example
    _ = pkg.delegateReader.Read
    _ = pkg.dumpConn.Example
    _ = pkg.failureToReadBody.Close
    _ = pkg.failureToReadBody.Read
    _ = pkg.maxLatencyWriter.Write
    _ = pkg.neverEnding.Read
    _ = pkg.noopCloseReader.Close
    _ = pkg.noopCloseReader.Read
}
