package cmd_test

import (
	"os"
	"testing"

	"github.com/SlashGordon/nas-manager/cmd"
)

func TestGetEnv(t *testing.T) {
	// Test with existing env var
	t.Setenv("TEST_VAR", "test_value")
	result := cmd.GetEnv("TEST_VAR", "default")
	if result != "test_value" {
		t.Errorf("Expected 'test_value', got '%s'", result)
	}

	// Test with default value
	result = cmd.GetEnv("NON_EXISTENT_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got '%s'", result)
	}

	os.Unsetenv("TEST_VAR")
}

func TestGetDDNSConfig(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test_token")
	t.Setenv("CF_ZONE_ID", "test_zone")
	t.Setenv("CF_RECORD_NAME", "test.example.com")

	config := cmd.GetDDNSConfig()

	if config.CFToken != "test_token" {
		t.Errorf("Expected 'test_token', got '%s'", config.CFToken)
	}
	if config.CFZoneID != "test_zone" {
		t.Errorf("Expected 'test_zone', got '%s'", config.CFZoneID)
	}
	if config.CFRecordName != "test.example.com" {
		t.Errorf("Expected 'test.example.com', got '%s'", config.CFRecordName)
	}

	os.Unsetenv("CF_API_TOKEN")
	os.Unsetenv("CF_ZONE_ID")
	os.Unsetenv("CF_RECORD_NAME")
}

func TestGetAcmeConfig(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test_token")
	t.Setenv("ACME_DOMAIN", "test.example.com")
	t.Setenv("ACME_EMAIL", "test@example.com")
	t.Setenv("ACME_CERT_PATH", "/custom/cert/path")

	config := cmd.GetAcmeConfig()

	if config.CFToken != "test_token" {
		t.Errorf("Expected 'test_token', got '%s'", config.CFToken)
	}
	if config.Domain != "test.example.com" {
		t.Errorf("Expected 'test.example.com', got '%s'", config.Domain)
	}
	if config.Email != "test@example.com" {
		t.Errorf("Expected 'test@example.com', got '%s'", config.Email)
	}
	if config.CertPath != "/custom/cert/path" {
		t.Errorf("Expected '/custom/cert/path', got '%s'", config.CertPath)
	}

	os.Unsetenv("CF_API_TOKEN")
	os.Unsetenv("ACME_DOMAIN")
	os.Unsetenv("ACME_EMAIL")
	os.Unsetenv("ACME_CERT_PATH")
}

func TestGetAcmeConfigDefaults(t *testing.T) {
	// Test default values when env vars are not set
	config := cmd.GetAcmeConfig()

	if config.CertPath != "./cert" {
		t.Errorf("Expected default cert path './cert', got '%s'", config.CertPath)
	}
}
