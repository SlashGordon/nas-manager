package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/utils"
)

// CheckSSHHardening checks SSH configuration
func CheckSSHHardening() []HardeningResult {
	var results []HardeningResult

	// Check if SSH is running
	sshRunning := isSSHRunning()
	message := "SSH service status"
	recommendation := "SSH service is not running. No action needed"
	if !sshRunning {
		return []HardeningResult{
			{false, message, recommendation},
		}
	}

	recommendation = "SSH service is running"

	// Check SSH configuration
	if content, readErr := fs.ReadFile("/etc/ssh/sshd_config"); readErr == nil {
		config := string(content)

		sshSettings := map[string]string{
			"PermitRootLogin":        "no",
			"PasswordAuthentication": "no",
			"PermitEmptyPasswords":   "no",
			"X11Forwarding":          "no",
			"MaxAuthTries":           "3",
			"ClientAliveInterval":    "300",
			"ClientAliveCountMax":    "2",
			"Protocol":               "2",
		}

		for setting, expected := range sshSettings {
			secure := strings.Contains(config, fmt.Sprintf("%s %s", setting, expected))
			settingMessage := fmt.Sprintf("SSH %s configuration", setting)
			settingRecommendation := fmt.Sprintf("Set %s to %s", setting, expected)
			if secure {
				settingRecommendation = fmt.Sprintf("%s is properly configured", setting)
			}

			results = append(results, HardeningResult{
				Secure:         secure,
				Message:        settingMessage,
				Recommendation: settingRecommendation,
			})
		}
	}

	results = append(results, HardeningResult{
		Secure:         sshRunning,
		Message:        message,
		Recommendation: recommendation,
	})

	return results
}

// ApplySSHHardening applies SSH security hardening.
func ApplySSHHardening() error {
	utils.PrintHeader("SSH Security Hardening")

	if !isSSHRunning() {
		fmt.Fprintln(os.Stdout, "SSH service is not running. Skipping SSH hardening.")
		return nil
	}

	if err := backupFile("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup"); err != nil {
		return err
	}

	config, err := fs.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	updated, modified := applySSHSettings(string(config))
	if modified {
		return fs.WriteFile("/etc/ssh/sshd_config", []byte(updated), 0644)
	}

	return nil
}

// isSSHRunning checks if the SSH service is running.
func isSSHRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "synoservice", "--status", "sshd")
	output, err := cmd.Output()
	return err == nil && strings.Contains(string(output), "start")
}

// backupFile creates a backup of a given file.
func backupFile(src, dst string) error {
	if err := fs.CopyFile(src, dst); err != nil {
		return fmt.Errorf("failed to backup %s: %w", src, err)
	}
	return nil
}

// applySSHSettings enforces secure SSH settings and returns updated config + flag if modified.
func applySSHSettings(config string) (string, bool) {
	settings := map[string]string{
		"PermitRootLogin":        "no",
		"PasswordAuthentication": "no",
		"PermitEmptyPasswords":   "no",
		"X11Forwarding":          "no",
		"MaxAuthTries":           "3",
		"ClientAliveInterval":    "300",
		"ClientAliveCountMax":    "2",
		"Protocol":               "2",
	}

	modified := false
	trusted := false

	for key, val := range settings {
		if hasSetting(config, key, val) {
			continue
		}

		choice := constants.ChoiceYes
		if !trusted {
			choice = PromptUser(fmt.Sprintf("Set %s to %s", key, val))
		}

		switch choice {
		case constants.ChoiceYes, constants.ChoiceTrust:
			fmt.Fprintf(os.Stdout, "Applying: %s %s\n", key, val)

			if choice == constants.ChoiceTrust {
				fmt.Fprintln(os.Stdout, "  → Trusting all remaining changes")
				trusted = true
			}

			config = upsertSetting(config, key, val)
			modified = true

		default:
			fmt.Fprintf(os.Stdout, "Skipped: %s\n", key)
		}
	}

	return config, modified
}

// hasSetting checks if the config already contains key-value.
func hasSetting(config, key, val string) bool {
	return strings.Contains(config, fmt.Sprintf("%s %s", key, val))
}

// upsertSetting replaces or appends a setting in the SSH config.
func upsertSetting(config, key, val string) string {
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			lines[i] = fmt.Sprintf("%s %s", key, val)
			return strings.Join(lines, "\n")
		}
	}
	return config + fmt.Sprintf("\n%s %s\n", key, val)
}
