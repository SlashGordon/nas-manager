package security

import (
	"context"
	"os/exec"
	"time"

	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/spf13/cobra"
)

var PortscanCmd = &cobra.Command{
	Use:   "portscan",
	Short: i18n.T(i18n.CmdPortscanShort),
	Long:  i18n.T(i18n.CmdPortscanLong),
}

var startPortscanCmd = &cobra.Command{
	Use:   "start",
	Short: i18n.T(i18n.CmdPortscanStartShort),
	Long:  i18n.T(i18n.CmdPortscanStartLong),
	Run: func(cmd *cobra.Command, args []string) {
		_ = args
		threshold := "10"
		window := "60"

		if err := setupPortscanRules(threshold, window); err != nil {
			cmd.PrintErrf("Error: %v\n", err)
			return
		}

		cmd.Printf("Port scan detection started (threshold: %s connections in %s seconds)\n", threshold, window)
	},
}

var stopPortscanCmd = &cobra.Command{
	Use:   "stop",
	Short: i18n.T(i18n.CmdPortscanStopShort),
	Long:  i18n.T(i18n.CmdPortscanStopLong),
	Run: func(cmd *cobra.Command, args []string) {
		_ = args
		if err := removePortscanRules(); err != nil {
			cmd.PrintErrf("Error: %v\n", err)
			return
		}

		cmd.Println("Port scan detection stopped")
	},
}

func setupPortscanRules(threshold, window string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create PORTSCAN chain
	cmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-N", "PORTSCAN")
	_ = cmd.Run() // Ignore error if chain already exists

	// Clear existing rules
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-F", "PORTSCAN")
	_ = cmd.Run()

	// Add port scan detection rule
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-A", "PORTSCAN",
		"-m", "recent", "--name", "portscan", "--update", "--seconds", window,
		"--hitcount", threshold, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Add rule to track new connections
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-A", "PORTSCAN",
		"-m", "recent", "--name", "portscan", "--set", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Accept all other traffic
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-A", "PORTSCAN", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Link to INPUT chain if not already linked
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-C", "INPUT", "-j", "PORTSCAN")
	if err := cmd.Run(); err != nil {
		cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-I", "INPUT", "1", "-j", "PORTSCAN")
		return cmd.Run()
	}

	return nil
}

func removePortscanRules() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Remove from INPUT chain
	cmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-D", "INPUT", "-j", "PORTSCAN")
	_ = cmd.Run() // Ignore error if rule doesn't exist

	// Flush chain
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-F", "PORTSCAN")
	_ = cmd.Run()

	// Delete chain
	cmd = exec.CommandContext(ctx, "iptables", "-t", "filter", "-X", "PORTSCAN")
	_ = cmd.Run()

	return nil
}

func init() {
	PortscanCmd.AddCommand(startPortscanCmd)
	PortscanCmd.AddCommand(stopPortscanCmd)
}
