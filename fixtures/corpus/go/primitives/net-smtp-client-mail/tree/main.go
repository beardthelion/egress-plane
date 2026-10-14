package main

import "net/smtp"

func main() {
	var c smtp.Client
	err := c.Mail("sender@example.com")
	_ = err
}
