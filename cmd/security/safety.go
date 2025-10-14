package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// SafetyManager handles automatic revert of blocklist changes if connection is lost.
type SafetyManager struct {
	clientIP    string
	chain       string
	revertTimer *time.Timer
	revertDelay time.Duration
	isActive    bool
}

func NewSafetyManager(chain string, delay time.Duration) *SafetyManager {
	return &SafetyManager{
		chain:       chain,
		revertDelay: delay,
		isActive:    false,
	}
}

func (sm *SafetyManager) Start() error {
	// Get client IP from SSH connection
	clientIP := getClientIP()
	if clientIP == "" {
		return errors.New("cannot determine client IP - safety mode disabled")
	}

	sm.clientIP = clientIP
	sm.isActive = true

	log.Infof("🛡️  Safety mode enabled for IP: %s", clientIP)
	log.Infof("⏰ Auto-revert in %v if connection lost", sm.revertDelay)

	// Set up signal handlers for graceful shutdown
	sm.setupSignalHandlers()

	// Start the safety timer
	sm.startRevertTimer()

	return nil
}

func (sm *SafetyManager) Stop() {
	if !sm.isActive {
		return
	}

	if sm.revertTimer != nil {
		sm.revertTimer.Stop()
		sm.revertTimer = nil
	}

	sm.isActive = false
	log.Info("✅ Safety mode disabled - changes are permanent")
}

func (sm *SafetyManager) Refresh() {
	if !sm.isActive {
		return
	}

	// Reset the timer
	if sm.revertTimer != nil {
		sm.revertTimer.Stop()
	}
	sm.startRevertTimer()
	log.Infof("🔄 Safety timer refreshed - %v remaining", sm.revertDelay)
}

func (sm *SafetyManager) startRevertTimer() {
	sm.revertTimer = time.AfterFunc(sm.revertDelay, func() {
		log.Warn("\n⚠️  Safety timeout reached - reverting blocklist changes!")
		if err := sm.revertChanges(); err != nil {
			log.Errorf("❌ Failed to revert changes: %v", err)
		} else {
			log.Info("✅ Blocklist changes reverted successfully")
		}
		os.Exit(0)
	})
}

func (sm *SafetyManager) revertChanges() error {
	ctx := context.Background()
	// Clear the blocklist chain
	if err := ClearChain(ctx, sm.chain); err != nil {
		return fmt.Errorf("failed to clear chain %s: %w", sm.chain, err)
	}

	// Remove the chain from INPUT
	cmd := exec.Command("iptables", "-t", "filter", "-D", "INPUT", "-j", sm.chain)
	cmd.Run() // Ignore error if not linked

	log.Infof("🔓 Cleared blocklist chain: %s", sm.chain)
	return nil
}

func (sm *SafetyManager) setupSignalHandlers() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Info("\n🛑 Interrupt received - stopping safety mode")
		sm.Stop()
		os.Exit(0)
	}()
}

func getClientIP() string {
	// Try to get IP from SSH_CLIENT environment variable
	if sshClient := os.Getenv("SSH_CLIENT"); sshClient != "" {
		parts := strings.Split(sshClient, " ")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Try to get IP from SSH_CONNECTION environment variable
	if sshConn := os.Getenv("SSH_CONNECTION"); sshConn != "" {
		parts := strings.Split(sshConn, " ")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Fallback: try to detect from active connections
	return detectClientIP()
}

func detectClientIP() string {
	output, err := exec.CommandContext(context.Background(), "netstat", "-tn").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, ":22 ") || !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		ip := parseForeignIP(line)
		if ip != "" && ip != "127.0.0.1" && ip != "::1" {
			return ip
		}
	}

	return ""
}

// parseForeignIP extracts the foreign address from a netstat line.
func parseForeignIP(line string) string {
	const foreignAddrIndex = 4

	fields := strings.Fields(line)
	if len(fields) <= foreignAddrIndex {
		return ""
	}

	host, _, err := net.SplitHostPort(fields[foreignAddrIndex])
	if err != nil {
		return ""
	}

	return host
}
