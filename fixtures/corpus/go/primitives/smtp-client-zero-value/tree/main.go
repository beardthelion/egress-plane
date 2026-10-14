package main

import "net/smtp"

func main() {
	var c smtp.Client
	c.Mail("from@example.com")
	c2 := smtp.Client{}
	c2.Mail("from@example.org")
}
