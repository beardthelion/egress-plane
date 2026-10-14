package main

import "net/smtp"

// The unexported auth and closer internals (cramMD5Auth, plainAuth,
// dataCloser) carry Next, Start, and Close members that stay inert.
func main() {
	var a smtp.Auth
	var s smtp.ServerInfo
	var c smtp.Client
	_, _, _ = a, s, c
	_ = smtp.CRAMMD5Auth
	_ = smtp.PlainAuth
	_ = c.Close
	_ = c.TLSConnectionState
	_ = smtp.cramMD5Auth.Next
	_ = smtp.cramMD5Auth.Start
	_ = smtp.dataCloser.Close
	_ = smtp.plainAuth.Next
	_ = smtp.plainAuth.Start
}
