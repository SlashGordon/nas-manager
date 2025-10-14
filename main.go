// Package main provides the entry point for the nas-manager CLI tool.
// nas-manager is a CLI tool for DDNS and certificate management.
package main

import (
	"github.com/SlashGordon/nas-manager/cmd"
	"github.com/SlashGordon/nas-manager/internal/logger"
)

func main() {
	log := logger.NewCLILogger()
	cmd.Execute(log)
}
