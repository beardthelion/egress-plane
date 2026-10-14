package main

import "net/smtp"

func main() {
	c, err := smtp.Dial("mail.example.com:25")
	_ = err
	_ = c
}
