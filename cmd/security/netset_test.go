package security_test

import (
	"github.com/SlashGordon/nas-manager/cmd/security"
	"os"
	"strings"
	"testing"
)

func TestNetsetToIptablesRules(t *testing.T) {
	tests := []struct {
		name     string
		netset   string
		expected []string
	}{
		{
			name:   "Single IP",
			netset: "192.168.1.1",
			expected: []string{
				"iptables -A BLOCKLIST -s 192.168.1.1 -j DROP",
			},
		},
		{
			name:   "CIDR Range",
			netset: "10.0.0.0/8",
			expected: []string{
				"iptables -A BLOCKLIST -s 10.0.0.0/8 -j DROP",
			},
		},
		{
			name: "Multiple entries with comments",
			netset: `# This is a comment
192.168.1.1
# Another comment
10.0.0.0/24

203.0.113.0/24`,
			expected: []string{
				"iptables -A BLOCKLIST -s 192.168.1.1 -j DROP",
				"iptables -A BLOCKLIST -s 10.0.0.0/24 -j DROP",
				"iptables -A BLOCKLIST -s 203.0.113.0/24 -j DROP",
			},
		},
		{
			name: "IPv6 addresses",
			netset: `2001:db8::1
2001:db8::/32`,
			expected: []string{
				"ip6tables -A BLOCKLIST -s 2001:db8::1 -j DROP",
				"ip6tables -A BLOCKLIST -s 2001:db8::/32 -j DROP",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := parseNetsetToRules(tt.netset, "BLOCKLIST")

			if len(rules) != len(tt.expected) {
				t.Errorf("Expected %d rules, got %d", len(tt.expected), len(rules))
				return
			}

			for i, rule := range rules {
				if rule != tt.expected[i] {
					t.Errorf("Rule %d: expected '%s', got '%s'", i, tt.expected[i], rule)
				}
			}
		})
	}
}

func parseNetsetToRules(netset, chain string) []string {
	var rules []string

	for _, line := range strings.Split(netset, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Determine if IPv4 or IPv6
		var cmd string
		if strings.Contains(line, ":") {
			cmd = "ip6tables"
		} else {
			cmd = "iptables"
		}

		rule := cmd + " -A " + chain + " -s " + line + " -j DROP"
		rules = append(rules, rule)
	}

	return rules
}

func TestGetBlocklistsDefault(t *testing.T) {
	// Test default behavior
	lists := security.GetBlocklists()
	if len(lists) != 3 {
		t.Errorf("Expected 3 default lists, got %d", len(lists))
	}

	expectedNames := []string{"firehol_level1", "spamhaus_drop", "dshield"}
	for i, list := range lists {
		if list.Name != expectedNames[i] {
			t.Errorf("Expected list name '%s', got '%s'", expectedNames[i], list.Name)
		}
	}
}

func TestGetBlocklistsCustomOnly(t *testing.T) {
	// Set custom lists environment variable
	oldCustom := os.Getenv("SECURITY_CUSTOM_LISTS")
	defer func() {
		if oldCustom == "" {
			os.Unsetenv("SECURITY_CUSTOM_LISTS")
		} else {
			t.Setenv("SECURITY_CUSTOM_LISTS", oldCustom)
		}
	}()

	t.Setenv("SECURITY_CUSTOM_LISTS", "custom1=http://example.com/list1,custom2=http://example.com/list2")

	lists := security.GetBlocklists()
	if len(lists) != 2 {
		t.Errorf("Expected 2 custom lists, got %d", len(lists))
	}

	if lists[0].Name != "custom1" || lists[1].Name != "custom2" {
		t.Errorf("Custom lists not parsed correctly")
	}
}

func TestGetBlocklistsSelectedDefaults(t *testing.T) {
	// Set selected defaults
	oldDefault := os.Getenv("SECURITY_DEFAULT_LISTS")
	defer func() {
		if oldDefault == "" {
			os.Unsetenv("SECURITY_DEFAULT_LISTS")
		} else {
			t.Setenv("SECURITY_DEFAULT_LISTS", oldDefault)
		}
	}()

	t.Setenv("SECURITY_DEFAULT_LISTS", "firehol_level1,dshield")

	lists := security.GetBlocklists()
	if len(lists) != 2 {
		t.Errorf("Expected 2 selected default lists, got %d", len(lists))
	}

	expectedNames := []string{"firehol_level1", "dshield"}
	for i, list := range lists {
		if list.Name != expectedNames[i] {
			t.Errorf("Expected list name '%s', got '%s'", expectedNames[i], list.Name)
		}
	}
}
