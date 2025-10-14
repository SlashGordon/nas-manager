package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
)

// CheckNetworkHardening checks network security settings
func CheckNetworkHardening() []HardeningResult {
	var results []HardeningResult

	networkSettings := map[string]string{
		"net.ipv4.ip_forward":                        "0",
		"net.ipv4.conf.all.send_redirects":           "0",
		"net.ipv4.conf.default.send_redirects":       "0",
		"net.ipv4.conf.all.accept_redirects":         "0",
		"net.ipv4.conf.default.accept_redirects":     "0",
		"net.ipv4.conf.all.secure_redirects":         "0",
		"net.ipv4.conf.default.secure_redirects":     "0",
		"net.ipv4.conf.all.accept_source_route":      "0",
		"net.ipv4.conf.default.accept_source_route":  "0",
		"net.ipv4.conf.all.log_martians":             "1",
		"net.ipv4.conf.default.log_martians":         "1",
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
		"net.ipv4.conf.all.rp_filter":                "1",
		"net.ipv4.conf.default.rp_filter":            "1",
		"net.ipv4.tcp_syncookies":                    "1",
		"net.ipv6.conf.all.accept_redirects":         "0",
		"net.ipv6.conf.default.accept_redirects":     "0",
		"net.ipv6.conf.all.accept_source_route":      "0",
		"net.ipv6.conf.default.accept_source_route":  "0",
	}

	for setting, expected := range networkSettings {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "sysctl", "-b", setting)
		if output, err := cmd.Output(); err == nil {
			current := strings.TrimSpace(string(output))
			secure := current == expected
			message := fmt.Sprintf("%s is %s", setting, current)
			recommendation := fmt.Sprintf("Set %s to %s", setting, expected)
			if secure {
				recommendation = fmt.Sprintf("%s is properly configured", setting)
			}
			results = append(results, HardeningResult{
				Secure:         secure,
				Message:        message,
				Recommendation: recommendation,
			})
		}
		cancel()
	}

	return results
}

// ApplyNetworkHardening applies network security hardening
func ApplyNetworkHardening() error {
	if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningTitle)+"\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(os.Stdout, strings.Repeat("=", len(i18n.T(i18n.NetworkHardeningTitle)))+"\n"); err != nil {
		return err
	}

	networkSettings := map[string]string{
		"net.ipv4.ip_forward":                        "0",
		"net.ipv4.conf.all.send_redirects":           "0",
		"net.ipv4.conf.default.send_redirects":       "0",
		"net.ipv4.conf.all.accept_redirects":         "0",
		"net.ipv4.conf.default.accept_redirects":     "0",
		"net.ipv4.conf.all.secure_redirects":         "0",
		"net.ipv4.conf.default.secure_redirects":     "0",
		"net.ipv4.conf.all.accept_source_route":      "0",
		"net.ipv4.conf.default.accept_source_route":  "0",
		"net.ipv4.conf.all.log_martians":             "1",
		"net.ipv4.conf.default.log_martians":         "1",
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
		"net.ipv4.conf.all.rp_filter":                "1",
		"net.ipv4.conf.default.rp_filter":            "1",
		"net.ipv4.tcp_syncookies":                    "1",
		"net.ipv6.conf.all.accept_redirects":         "0",
		"net.ipv6.conf.default.accept_redirects":     "0",
		"net.ipv6.conf.all.accept_source_route":      "0",
		"net.ipv6.conf.default.accept_source_route":  "0",
	}

	sysctlConf := "/etc/sysctl.conf"
	content := ""
	modified := false
	trusted := false

	// Read existing content
	if existingContent, err := os.ReadFile(sysctlConf); err == nil {
		content = string(existingContent)
	}

	// Check if we need to apply settings
	needsUpdate := false
	for setting, value := range networkSettings {
		if !strings.Contains(content, fmt.Sprintf("%s = %s", setting, value)) {
			needsUpdate = true
			break
		}
	}

	if needsUpdate {
		choice := constants.ChoiceYes
		if !trusted {
			choice = PromptUser("Apply network security hardening")
		}

		if choice == constants.ChoiceYes || choice == constants.ChoiceTrust {
			if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningApply)+"\n"); err != nil {
				return err
			}

			if choice == constants.ChoiceTrust {
				if _, err := fmt.Fprintf(os.Stdout, "  %s\n", i18n.T(i18n.TrustingRemaining)); err != nil {
					return err
				}
			}

			// Add settings to sysctl.conf
			for setting, value := range networkSettings {
				settingLine := fmt.Sprintf("%s = %s", setting, value)
				if !strings.Contains(content, settingLine) {
					content += fmt.Sprintf("\n# Network security hardening\n%s\n", settingLine)
					if _, err := fmt.Fprintf(os.Stdout, i18n.T(i18n.NetworkHardeningAdded)+"\n", settingLine); err != nil {
						return err
					}
					modified = true
				}
			}

			if modified {
				if err := os.WriteFile(sysctlConf, []byte(content), 0600); err != nil {
					return fmt.Errorf("failed to write sysctl.conf: %w", err)
				}

				// Apply settings immediately
				for setting, value := range networkSettings {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					cmd := exec.CommandContext(ctx, "sysctl", fmt.Sprintf("%s=%s", setting, value))
					if err := cmd.Run(); err != nil {
						if _, writeErr := fmt.Fprintf(os.Stderr, i18n.T(i18n.NetworkHardeningFailed)+"\n", setting, err); writeErr != nil {
							cancel()
							return writeErr
						}
					}
					cancel()
				}

				if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningApplied)+"\n"); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningConfigured)+"\n"); err != nil {
					return err
				}
			}
		} else {
			if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningSkipped)+"\n"); err != nil {
				return err
			}
		}
	} else {
		if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.NetworkHardeningConfigured)+"\n"); err != nil {
			return err
		}
	}

	return nil
}
