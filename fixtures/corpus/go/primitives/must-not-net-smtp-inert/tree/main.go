package main

import pkg "net/smtp"

func main() {
    _ = pkg.Auth
    _ = pkg.CRAMMD5Auth
    _ = pkg.Client.Close
    _ = pkg.Client.TLSConnectionState
    _ = pkg.PlainAuth
    _ = pkg.ServerInfo
    _ = pkg.cramMD5Auth.Next
    _ = pkg.cramMD5Auth.Start
    _ = pkg.dataCloser.Close
    _ = pkg.plainAuth.Next
    _ = pkg.plainAuth.Start
}
