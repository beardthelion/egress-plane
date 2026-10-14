package main

import "net/smtp"

func main() {
	err := smtp.SendMail("smtp.example.com:25", nil, "a@example.com",
		[]string{"b@example.com"}, nil)
	_ = err
}
