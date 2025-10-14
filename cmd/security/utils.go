package security

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// runIptables executes an iptables command with a timeout and returns combined output.
func runIptables(ctx context.Context, args ...string) error {
	// default timeout of 5 seconds
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(c, "iptables", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables %v failed: %w (stderr: %s)", args, err, stderr.String())
	}
	return nil
}

// CreateChain creates a new chain if it does not already exist.
func CreateChain(ctx context.Context, chain string) error {
	// Try creating the chain; if it exists, iptables will return an error.
	err := runIptables(ctx, "-t", "filter", "-N", chain)
	if err != nil && !isChainExistsError(err) {
		return err
	}
	return nil
}

// ClearChain removes all rules from the given chain.
func ClearChain(ctx context.Context, chain string) error {
	return runIptables(ctx, "-t", "filter", "-F", chain)
}

// LinkChain ensures the custom chain is referenced at the top of INPUT.
func LinkChain(ctx context.Context, chain string) error {
	// Check if already linked
	check := exec.CommandContext(ctx, "iptables", "-t", "filter", "-C", "INPUT", "-j", chain)
	if err := check.Run(); err == nil {
		return nil // already linked
	}

	return runIptables(ctx, "-t", "filter", "-I", "INPUT", "1", "-j", chain)
}

// AddDropRule appends a DROP rule for the given IP in the specified chain.
func AddDropRule(ctx context.Context, chain, ip string) error {
	return runIptables(ctx, "-t", "filter", "-A", chain, "-s", ip, "-j", "DROP")
}

// isChainExistsError tries to detect if the iptables error is just "chain already exists".
func isChainExistsError(err error) bool {
	return err != nil && (bytes.Contains([]byte(err.Error()), []byte("Chain already exists")))
}
