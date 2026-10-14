package main

import (
	"context"
	"os/exec"
)

func main() {
	cmd := exec.CommandContext(context.Background(), "curl", "https://api.example.com/v1/ping")
	_ = cmd
}
