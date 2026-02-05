package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// loadConfig loads configuration from an env-style file (KEY=VALUE).
// This is invoked via cobra.OnInitialize so it runs before command execution.
func loadConfig() {
	path := strings.TrimSpace(configFile)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("NAS_MANAGER_CONFIG"))
	}
	if path == "" {
		// Backwards compatible with existing docs/examples.
		path = strings.TrimSpace(os.Getenv("NAS_CONFIG"))
	}
	if path == "" {
		if fileExists(".nasrc") {
			path = ".nasrc"
		} else if fileExists("env.nas") {
			path = "env.nas"
		} else if home, err := os.UserHomeDir(); err == nil {
			homeNasrc := filepath.Join(home, ".nasrc")
			if fileExists(homeNasrc) {
				path = homeNasrc
			}
		}
	}
	if path == "" {
		return
	}

	if err := loadEnvFile(path, configOverride); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config file %s: %v\n", path, err)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func loadEnvFile(path string, override bool) error {
	clean := filepath.Clean(path)
	f, err := os.Open(clean)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var scanErrs []error
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		// Strip inline comments: KEY=value # comment
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		value = unquoteEnvValue(value)

		if !override {
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
		}
		if err := os.Setenv(key, value); err != nil {
			scanErrs = append(scanErrs, err)
		}
	}
	if err := scanner.Err(); err != nil {
		scanErrs = append(scanErrs, err)
	}
	return errors.Join(scanErrs...)
}

func unquoteEnvValue(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}
