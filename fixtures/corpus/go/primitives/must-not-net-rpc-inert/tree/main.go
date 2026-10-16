package main

import pkg "net/rpc"

func main() {
    _ = pkg.Call
    _ = pkg.Client.Close
    _ = pkg.ClientCodec
    _ = pkg.DefaultDebugPath
    _ = pkg.DefaultRPCPath
    _ = pkg.ErrShutdown
    _ = pkg.ReExample
    _ = pkg.Server.Register
    _ = pkg.Server.RegisterName
    _ = pkg.ServerCodec
    _ = pkg.ServerError
    _ = pkg.ServerError.Error
    _ = pkg.debugHTTP.ServeHTTP
    _ = pkg.gobClientCodec.Example
    _ = pkg.gobServerCodec.Example
    _ = pkg.methodArray.Example
    _ = pkg.methodType.NumCalls
    _ = pkg.serviceArray.Example
}
