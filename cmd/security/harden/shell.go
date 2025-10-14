package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
)

// CheckShellHistory checks shell history configuration
func CheckShellHistory() []HardeningResult {
	var results []HardeningResult

	bashrc := "/root/.bashrc"
	histSize := constants.HistorySize

	// Check if bashrc exists and has proper history settings
	if content, err := os.ReadFile(bashrc); err == nil {
		config := string(content)

		// Check HISTSIZE
		histSizeSecure := strings.Contains(config, fmt.Sprintf("HISTSIZE=%d", histSize))
		histSizeMessage := "Shell history size configuration"
		histSizeRecommendation := fmt.Sprintf("Set HISTSIZE to %d", histSize)
		if histSizeSecure {
			histSizeRecommendation = "Shell history size is properly configured"
		}

		results = append(results, HardeningResult{
			Secure:         histSizeSecure,
			Message:        histSizeMessage,
			Recommendation: histSizeRecommendation,
		})

		// Check HISTFILESIZE
		histFileSizeSecure := strings.Contains(config, fmt.Sprintf("HISTFILESIZE=%d", histSize))
		histFileSizeMessage := "Shell history file size configuration"
		histFileSizeRecommendation := fmt.Sprintf("Set HISTFILESIZE to %d", histSize)
		if histFileSizeSecure {
			histFileSizeRecommendation = "Shell history file size is properly configured"
		}

		results = append(results, HardeningResult{
			Secure:         histFileSizeSecure,
			Message:        histFileSizeMessage,
			Recommendation: histFileSizeRecommendation,
		})
	} else {
		results = append(results, HardeningResult{
			Secure:         false,
			Message:        "Shell history configuration file missing",
			Recommendation: "Create and configure shell history settings",
		})
	}

	// Check history file size
	histPath := "/root/.bash_history"
	if info, err := os.Stat(histPath); err == nil {
		size := info.Size()
		secure := size <= 10000 // Arbitrary threshold
		message := fmt.Sprintf("History file size is %d bytes", size)
		recommendation := "Clear or reduce history file size"
		if secure {
			recommendation = "History file size is acceptable"
		}

		results = append(results, HardeningResult{
			Secure:         secure,
			Message:        message,
			Recommendation: recommendation,
		})
	}

	return results
}

// ApplyShellHardening applies shell history hardening
func ApplyShellHardening() error {
	if err := printShellHeader(); err != nil {
		return err
	}

	bashrc := "/root/.bashrc"
	histSize := constants.HistorySize

	if needsHistoryUpdate(bashrc, histSize) {
		return applyHistorySettings(bashrc, histSize)
	}

	return nil
}

// printShellHeader prints the shell hardening header
func printShellHeader() error {
	title := i18n.T(i18n.ShellHistoryTitle)
	if _, err := fmt.Fprint(os.Stdout, title+"\n"); err != nil {
		return err
	}
	_, err := fmt.Fprint(os.Stdout, strings.Repeat("=", len(title))+"\n")
	return err
}

// needsHistoryUpdate checks if bashrc needs history configuration updates
func needsHistoryUpdate(bashrc string, histSize int) bool {
	existing, err := os.ReadFile(bashrc)
	if err != nil {
		return true
	}
	content := string(existing)
	return !strings.Contains(content, fmt.Sprintf("HISTSIZE=%d", histSize)) ||
		!strings.Contains(content, fmt.Sprintf("HISTFILESIZE=%d", histSize))
}

// applyHistorySettings applies history configuration with user confirmation
func applyHistorySettings(bashrc string, histSize int) error {
	choice := PromptUser(fmt.Sprintf("Set history size to %d entries", histSize))
	if choice != constants.ChoiceYes && choice != constants.ChoiceTrust {
		return nil
	}

	if err := printApplyingMessage(histSize, choice); err != nil {
		return err
	}

	if err := updateBashrc(bashrc, histSize); err != nil {
		return err
	}

	return clearHistoryFiles()
}

// printApplyingMessage prints the applying message
func printApplyingMessage(histSize int, choice string) error {
	if _, err := fmt.Fprintf(os.Stdout, "Auto-applying: %s\n", fmt.Sprintf(i18n.T(i18n.ShellHistorySize), histSize)); err != nil {
		return err
	}
	if choice == constants.ChoiceTrust {
		_, err := fmt.Fprintf(os.Stdout, "  %s\n", i18n.T(i18n.TrustingRemaining))
		return err
	}
	return nil
}

// updateBashrc updates the bashrc file with history settings
func updateBashrc(bashrc string, histSize int) error {
	content := ""
	if existing, err := os.ReadFile(bashrc); err == nil {
		content = string(existing)
	}

	if strings.Contains(content, "Shell history hardening") {
		return nil
	}

	historyConfig := fmt.Sprintf(`
# Shell history hardening
export HISTSIZE=%d
export HISTFILESIZE=%d
export HISTCONTROL=ignoredups:erasedups
`, histSize, histSize)

	content += historyConfig
	if err := os.WriteFile(bashrc, []byte(content), 0600); err != nil {
		_, printErr := fmt.Fprintf(os.Stderr, i18n.T(i18n.ShellHistoryFailed)+"\n", err)
		if printErr != nil {
			return printErr
		}
		return err
	}
	_, err := fmt.Fprint(os.Stdout, i18n.T(i18n.ShellHistoryConfigured)+"\n")
	return err
}

// clearHistoryFiles clears existing bash history files
func clearHistoryFiles() error {
	historyFiles := []string{"/root/.bash_history", "/home/*/.bash_history"}

	for _, pattern := range historyFiles {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, histFile := range matches {
			if err := clearSingleHistoryFile(histFile); err != nil {
				return err
			}
		}
	}
	return nil
}

// clearSingleHistoryFile clears a single history file
func clearSingleHistoryFile(histFile string) error {
	if _, err := os.Stat(histFile); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "truncate", "-s", "0", histFile).Run(); err == nil {
		_, err := fmt.Fprintf(os.Stdout, i18n.T(i18n.ShellHistoryCleared)+"\n", histFile)
		return err
	}
	return nil
}
