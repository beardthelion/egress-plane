package main

import "golang.org/x/net/websocket"

func main() {
	ws, err := websocket.Dial("wss://ws.example.com/socket", "", "https://origin.example.com")
	_ = err
	_ = ws
}
