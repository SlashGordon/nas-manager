package i18n_test

import (
	"os"
	"strings"
	"testing"

	"github.com/SlashGordon/nas-manager/internal/i18n"
)

func TestSetLanguage(t *testing.T) {
	i18n.SetLanguage("de")
	// Test by checking if German translation is returned
	result := i18n.T(i18n.SecurityScanTitle)
	if !strings.Contains(result, "Sicherheit") {
		t.Errorf("Expected German translation, got '%s'", result)
	}

	i18n.SetLanguage("invalid")
	// Test by checking if it falls back to English
	result = i18n.T(i18n.SecurityScanTitle)
	if !strings.Contains(result, "Security") {
		t.Errorf("Expected fallback to English, got '%s'", result)
	}
}

func TestT(t *testing.T) {
	i18n.SetLanguage("en")
	result := i18n.T(i18n.SecurityScanTitle)
	expected := "Synology NAS Security Hardening Scan"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}

	i18n.SetLanguage("de")
	result = i18n.T(i18n.SecurityScanTitle)
	expected = "Synology NAS Sicherheitshärtung Scan"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}

	result = i18n.T("nonexistent.key")
	if result != "nonexistent.key" {
		t.Errorf("Expected fallback to key, got '%s'", result)
	}
}

func TestInit(t *testing.T) {
	oldLang := os.Getenv("LANG")
	defer t.Setenv("LANG", oldLang)

	t.Setenv("LANG", "de_DE.UTF-8")
	// Reset to English first
	i18n.SetLanguage("en")

	// Simulate init by calling SetLanguage with parsed LANG
	if lang := os.Getenv("LANG"); lang != "" {
		if code := strings.Split(lang, "_")[0]; code != "" {
			i18n.SetLanguage(code)
		}
	}

	// Test by checking if German translation is returned
	result := i18n.T(i18n.SecurityScanTitle)
	if !strings.Contains(result, "Sicherheit") {
		t.Errorf("Expected German translation after init, got '%s'", result)
	}
}
