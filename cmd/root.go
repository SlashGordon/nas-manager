// Package cmd provides the command-line interface for nas-manager.
// It includes commands for DDNS management and ACME certificate operations.
package cmd

import (
	"fmt"
	"os"

	"github.com/SlashGordon/nas-manager/cmd/security"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/SlashGordon/nas-manager/internal/logger"
	"github.com/spf13/cobra"
)

// Build information set by ldflags
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Global logger instance
var log *logger.Logger

// setLogger sets the global logger instance
func setLogger(l *logger.Logger) {
	log = l
	security.SetLogger(l)
}

// GetLogger returns the global logger instance
func GetLogger() *logger.Logger {
	return log
}

var rootCmd = &cobra.Command{
	Use:   "nas-manager",
	Short: "Comprehensive CLI tool for managing and securing your Synology NAS system",
	Long: `
███╗   ██╗ █████╗ ███████╗    ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗ 
████╗  ██║██╔══██╗██╔════╝    ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
██╔██╗ ██║███████║███████╗    ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
██║╚██╗██║██╔══██║╚════██║    ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
██║ ╚████║██║  ██║███████║    ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

A comprehensive CLI tool for managing and securing your Synology NAS system.

🌐 NETWORK & DNS:
  • DDNS Management: Update Cloudflare DNS records
  • ACME Certificates: Issue/renew Let's Encrypt certificates

🛡️  SECURITY & PROTECTION:
  • IP Blocklists: Block malicious IPs using 12+ threat intelligence sources
  • Port Scan Detection: Automatically detect and block scanning attempts
  • Vulnerability Scanning: Scan open ports and services

🔒 SYSTEM HARDENING:
  • SSH, DSM, and kernel security hardening
  • Network security optimization
  • Service management and shell history reduction

Designed specifically for Synology NAS systems with enterprise-grade security.`,
	Version: Version,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: i18n.T(i18n.CmdVersionShort),
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := fmt.Fprintf(os.Stdout, i18n.T(i18n.VersionInfo)+"\n", Version, Commit, Date); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing version info: %v\n", err)
		}
	},
}

// Execute runs the root command
func Execute(log *logger.Logger) {
	setLogger(log)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprint(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}

func init() {
	loadConfig()
	rootCmd.AddCommand(acmeCmd)
	rootCmd.AddCommand(ddnsCmd)
	rootCmd.AddCommand(securityCmd)
	rootCmd.AddCommand(versionCmd)
}
