package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
)

// CheckKernelHardening checks kernel security settings
func CheckKernelHardening() []HardeningResult {
	var results []HardeningResult

	// Check ptrace scope
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cmd := exec.CommandContext(ctx, "sysctl", "-b", "kernel.yama.ptrace_scope")
	if output, err := cmd.Output(); err == nil {
		if value, parseErr := strconv.Atoi(strings.TrimSpace(string(output))); parseErr == nil {
			secure := value >= constants.PtraceScope
			message := fmt.Sprintf("Ptrace scope is %d", value)
			recommendation := fmt.Sprintf("Set ptrace scope to %d", constants.PtraceScope)
			if secure {
				recommendation = "Ptrace scope is properly configured"
			}
			results = append(results, HardeningResult{
				Secure:         secure,
				Message:        message,
				Recommendation: recommendation,
			})
		}
	}
	cancel()

	// Check core pattern
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	cmd = exec.CommandContext(ctx, "sysctl", "-b", "kernel.core_pattern")
	if output, err := cmd.Output(); err == nil {
		pattern := strings.TrimSpace(string(output))
		secure := !strings.Contains(pattern, "|")
		message := fmt.Sprintf("Core pattern is %s", pattern)
		recommendation := "Set core pattern to 'core'"
		if secure {
			recommendation = "Core pattern is properly configured"
		}
		results = append(results, HardeningResult{
			Secure:         secure,
			Message:        message,
			Recommendation: recommendation,
		})
	}
	cancel()

	// Check ASLR
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	cmd = exec.CommandContext(ctx, "sysctl", "-b", "kernel.randomize_va_space")
	if output, err := cmd.Output(); err == nil {
		if value, parseErr := strconv.Atoi(strings.TrimSpace(string(output))); parseErr == nil {
			secure := value >= 2
			message := fmt.Sprintf("ASLR is set to %d", value)
			recommendation := "Set ASLR to 2"
			if secure {
				recommendation = "ASLR is properly configured"
			}
			results = append(results, HardeningResult{
				Secure:         secure,
				Message:        message,
				Recommendation: recommendation,
			})
		}
	}
	cancel()

	return results
}

// ApplyKernelHardening applies kernel security hardening
func ApplyKernelHardening() error {
	if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningTitle)+"\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(os.Stdout, strings.Repeat("=", len(i18n.T(i18n.KernelHardeningTitle)))+"\n"); err != nil {
		return err
	}

	kernelSettings := map[string]string{
		"kernel.yama.ptrace_scope":  "2",
		"kernel.core_pattern":       "core",
		"kernel.randomize_va_space": "2",
		"kernel.kptr_restrict":      "2",
		"kernel.dmesg_restrict":     "1",
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
	for setting, value := range kernelSettings {
		if !strings.Contains(content, fmt.Sprintf("%s = %s", setting, value)) {
			needsUpdate = true
			break
		}
	}

	if needsUpdate {
		choice := constants.ChoiceYes
		if !trusted {
			choice = PromptUser("Apply kernel security hardening")
		}

		if choice == constants.ChoiceYes || choice == constants.ChoiceTrust {
			if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningApply)+"\n"); err != nil {
				return err
			}

			if choice == constants.ChoiceTrust {
				if _, err := fmt.Fprintf(os.Stdout, "  %s\n", i18n.T(i18n.TrustingRemaining)); err != nil {
					return err
				}
			}

			// Add settings to sysctl.conf
			for setting, value := range kernelSettings {
				settingLine := fmt.Sprintf("%s = %s", setting, value)
				if !strings.Contains(content, settingLine) {
					content += fmt.Sprintf("\n# Kernel security hardening\n%s\n", settingLine)
					if _, err := fmt.Fprintf(os.Stdout, i18n.T(i18n.KernelHardeningAdded)+"\n", settingLine); err != nil {
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
				for setting, value := range kernelSettings {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					cmd := exec.CommandContext(ctx, "sysctl", fmt.Sprintf("%s=%s", setting, value))
					if err := cmd.Run(); err != nil {
						if _, writeErr := fmt.Fprintf(os.Stderr, i18n.T(i18n.KernelHardeningFailed)+"\n", setting, err); writeErr != nil {
							cancel()
							return writeErr
						}
					}
					cancel()
				}

				if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningApplied)+"\n"); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningConfigured)+"\n"); err != nil {
					return err
				}
			}
		} else {
			if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningSkipped)+"\n"); err != nil {
				return err
			}
		}
	} else {
		if _, err := fmt.Fprint(os.Stdout, i18n.T(i18n.KernelHardeningConfigured)+"\n"); err != nil {
			return err
		}
	}

	return nil
}
