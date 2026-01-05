package security

import (
	"testing"
)

func TestReplacePlaceholders(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		ipv4       string
		ipv6       string
		expected   string
	}{
		{
			name:       "Replace PUBLIC_IP with IPv4",
			expression: "ip.src in {{{PUBLIC_IP}}}",
			ipv4:       "203.0.113.1",
			ipv6:       "2001:db8::1",
			expected:   "ip.src in {203.0.113.1}",
		},
		{
			name:       "Replace PUBLIC_IPV4",
			expression: "ip.src in {{{PUBLIC_IPV4}}}",
			ipv4:       "203.0.113.1",
			ipv6:       "",
			expected:   "ip.src in {203.0.113.1}",
		},
		{
			name:       "Replace PUBLIC_IPV6",
			expression: "ip.src in {{{PUBLIC_IPV6}}}",
			ipv4:       "",
			ipv6:       "2001:db8::1",
			expected:   "ip.src in {2001:db8::1}",
		},
		{
			name:       "Replace with CIDR notation IPv4",
			expression: "ip.src in {{{PUBLIC_IPV4/24}}}",
			ipv4:       "203.0.113.1",
			ipv6:       "",
			expected:   "ip.src in {203.0.113.1/24}",
		},
		{
			name:       "Replace with CIDR notation IPv6",
			expression: "ip.src in {{{PUBLIC_IPV6/64}}}",
			ipv4:       "",
			ipv6:       "2001:db8::1",
			expected:   "ip.src in {2001:db8::1/64}",
		},
		{
			name: "Complex expression with multiple placeholders",
			expression: "(not ip.src in {{{PUBLIC_IPV4/24}}} and http.host wildcard \"gitea.example.com\") or " +
				"(http.host wildcard \"media.example.com\" and not ip.src in {{{PUBLIC_IPV6/64}}})",
			ipv4: "203.0.113.1",
			ipv6: "2001:db8::1",
			expected: "(not ip.src in {203.0.113.1/24} and http.host wildcard \"gitea.example.com\") or " +
				"(http.host wildcard \"media.example.com\" and not ip.src in {2001:db8::1/64})",
		},
		{
			name:       "No placeholders",
			expression: "ip.src in {203.0.113.0/24}",
			ipv4:       "203.0.113.1",
			ipv6:       "",
			expected:   "ip.src in {203.0.113.0/24}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReplacePlaceholders(tt.expression, tt.ipv4, tt.ipv6)
			if result != tt.expected {
				t.Errorf("ReplacePlaceholders() = %v, want %v", result, tt.expected)
			}
		})
	}
}
