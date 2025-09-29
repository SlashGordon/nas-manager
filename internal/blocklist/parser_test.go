package blocklist_test

import (
	"testing"

	"github.com/SlashGordon/nas-manager/internal/blocklist"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		listName string
		expected string
	}{
		{"Plain IP", "192.168.1.1", "plain", "192.168.1.1"},
		{"Plain CIDR", "192.168.1.0/24", "plain", "192.168.1.0/24"},
		{"Tor exit address", "ExitAddress 1.2.3.4 2023-01-01 12:00:00", "tor_exits", "1.2.3.4"},
		{"Spamhaus format", "1.2.3.4/24 ; SBL123", "spamhaus", "1.2.3.4/24"},
		{"Comment line", "# This is a comment", "plain", ""},
		{"Empty line", "", "plain", ""},
		{"Invalid format", "invalid line", "plain", ""},
		{"Tor invalid", "Invalid tor line", "tor_exits", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := blocklist.ParseLine(tt.line, tt.listName)
			if result != tt.expected {
				t.Errorf("ParseLine(%q, %q) = %q, want %q", tt.line, tt.listName, result, tt.expected)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Valid IPv4", "192.168.1.1", true},
		{"Valid CIDR", "192.168.1.0/24", true},
		{"Invalid IP", "999.999.999.999", false},
		{"Invalid CIDR", "192.168.1.0/99", false},
		{"Empty string", "", false},
		{"Text", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := blocklist.ValidateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("ValidateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
