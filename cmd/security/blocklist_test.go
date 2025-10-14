package security_test

import (
	"strings"
	"testing"

	"github.com/SlashGordon/nas-manager/cmd/security"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/logger"
)

func TestExtractAndMergeIPsWithFilters(t *testing.T) {
	// Create test file with mixed IPs
	testFile := "/tmp/test_mixed_ips.txt"
	data := `# Mixed IP test data
# Local/Private IPs
192.168.1.1
10.0.0.1
172.16.0.1
127.0.0.1
169.254.1.1
# Public IPs
8.8.8.8
1.1.1.1
203.0.113.1
# Cloudflare IPs (common ranges)
104.16.0.1
172.64.0.1
# CIDR ranges
192.168.0.0/24
8.8.8.0/24`

	fs.WriteFile(testFile, []byte(data), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"test_mixed", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	tests := []struct {
		name             string
		filterCloudflare bool
		filterLocal      bool
		minExpected      int
		maxExpected      int
		description      string
	}{
		{
			name:             "No filters",
			filterCloudflare: false,
			filterLocal:      false,
			minExpected:      10,
			maxExpected:      15,
			description:      "Should include all valid IPs",
		},
		{
			name:             "Filter local only",
			filterCloudflare: false,
			filterLocal:      true,
			minExpected:      3,
			maxExpected:      8,
			description:      "Should exclude private/local IPs",
		},
		{
			name:             "Filter both",
			filterCloudflare: true,
			filterLocal:      true,
			minExpected:      2,
			maxExpected:      6,
			description:      "Should exclude both local and Cloudflare IPs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := security.ExtractAndMergeIPs(lists, tt.filterCloudflare, tt.filterLocal)
			if err != nil {
				t.Errorf("ExtractAndMergeIPs failed: %v", err)
				return
			}

			if len(ips) < tt.minExpected || len(ips) > tt.maxExpected {
				t.Errorf("%s: expected %d-%d IPs, got %d", tt.description, tt.minExpected, tt.maxExpected, len(ips))
			}

			// Verify no local IPs when filtering is enabled
			if tt.filterLocal {
				for _, ip := range ips {
					if isLocalIP(ip) {
						t.Errorf("Found local IP %s when local filtering enabled", ip)
					}
				}
			}
		})
	}
}

func TestTorExitAddressParsing(t *testing.T) {
	testFile := "/tmp/test_tor_regex.txt"
	torData := `# Tor exit addresses with regex parsing
ExitAddress 1.2.3.4 2023-01-01 12:00:00
ExitAddress 5.6.7.8 2023-01-01 12:01:00
# Invalid lines should be ignored
Invalid line without ExitAddress
ExitAddress invalid-ip 2023-01-01 12:02:00
ExitAddress 9.10.11.12 2023-01-01 12:03:00`

	fs.WriteFile(testFile, []byte(torData), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"tor_exits", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	ips, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	expectedIPs := []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}
	if len(ips) != len(expectedIPs) {
		t.Errorf("Expected %d Tor IPs, got %d", len(expectedIPs), len(ips))
	}

	// Verify all expected IPs are present
	ipMap := make(map[string]bool)
	for _, ip := range ips {
		ipMap[ip] = true
	}

	for _, expectedIP := range expectedIPs {
		if !ipMap[expectedIP] {
			t.Errorf("Expected Tor IP %s not found", expectedIP)
		}
	}
}

func TestSpamhausFormatParsing(t *testing.T) {
	testFile := "/tmp/test_spamhaus.txt"
	spamhausData := `# Spamhaus format test
1.2.3.0/24 ; SBL123 - Test entry
5.6.7.0/24 ; SBL456 - Another entry
# Plain IP without semicolon should not match spamhaus parser
8.8.8.8
# Invalid CIDR should be ignored
999.999.999.0/24 ; Invalid`

	fs.WriteFile(testFile, []byte(spamhausData), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"spamhaus", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	ips, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	// Should parse 2 valid CIDR ranges and 1 plain IP (fallback parser)
	expectedCount := 3
	if len(ips) != expectedCount {
		t.Errorf("Expected %d IPs, got %d", expectedCount, len(ips))
	}

	// Verify CIDR ranges are present
	found := make(map[string]bool)
	for _, ip := range ips {
		found[ip] = true
	}

	expectedEntries := []string{"1.2.3.0/24", "5.6.7.0/24", "8.8.8.8"}
	for _, entry := range expectedEntries {
		if !found[entry] {
			t.Errorf("Expected entry %s not found", entry)
		}
	}
}

// Helper function to check if an IP is local/private
func isLocalIP(ipStr string) bool {
	// Simple check for common private ranges
	return strings.HasPrefix(ipStr, "192.168.") ||
		strings.HasPrefix(ipStr, "10.") ||
		strings.HasPrefix(ipStr, "172.16.") ||
		strings.HasPrefix(ipStr, "172.17.") ||
		strings.HasPrefix(ipStr, "172.18.") ||
		strings.HasPrefix(ipStr, "172.19.") ||
		strings.HasPrefix(ipStr, "172.2") ||
		strings.HasPrefix(ipStr, "172.30.") ||
		strings.HasPrefix(ipStr, "172.31.") ||
		strings.HasPrefix(ipStr, "127.") ||
		strings.HasPrefix(ipStr, "169.254.")
}
