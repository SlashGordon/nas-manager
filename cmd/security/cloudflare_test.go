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
		wantErr    bool
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
		{
			name:       "Replace IPv6 network identifier",
			expression: "ip.src in {{{PUBLIC_IPV6_NETWORK}}}",
			ipv4:       "",
			ipv6:       "2001:db8:abcd:1234:5678:90ab:cdef:1234",
			expected:   "ip.src in {2001:db8:abcd:1234::}",
		},
		{
			name:       "Replace IPv6 network identifier with CIDR",
			expression: "ip.src in {{{PUBLIC_IPV6_NETWORK/64}}}",
			ipv4:       "",
			ipv6:       "2001:db8:abcd:1234:5678:90ab:cdef:1234",
			expected:   "ip.src in {2001:db8:abcd:1234::/64}",
		},
		{
			name:       "Replace IPv6 interface identifier",
			expression: "ip.src in {{{PUBLIC_IPV6_INTERFACE}}}",
			ipv4:       "",
			ipv6:       "2001:db8:abcd:1234:5678:90ab:cdef:1234",
			expected:   "ip.src in {::5678:90ab:cdef:1234}",
		},
		{
			name: "Complex expression with IPv6 parts",
			expression: "(not ip.src in {{{PUBLIC_IPV6_NETWORK/64}}} and http.host wildcard \"internal.example.com\") or " +
				"(ip.src in {{{PUBLIC_IPV6_INTERFACE}}})",
			ipv4: "",
			ipv6: "2001:db8:abcd:1234:5678:90ab:cdef:1234",
			expected: "(not ip.src in {2001:db8:abcd:1234::/64} and http.host wildcard \"internal.example.com\") or " +
				"(ip.src in {::5678:90ab:cdef:1234})",
		},
		{
			name:       "Error when IPv6 network placeholder but no IPv6",
			expression: "ip.src in {{{PUBLIC_IPV6_NETWORK/64}}}",
			ipv4:       "203.0.113.1",
			ipv6:       "",
			expected:   "ip.src in {{{PUBLIC_IPV6_NETWORK/64}}}",
			wantErr:    true,
		},
		{
			name:       "Error when IPv6 CIDR placeholder but no IPv6",
			expression: "ip.src in {{{PUBLIC_IPV6/64}}}",
			ipv4:       "203.0.113.1",
			ipv6:       "",
			expected:   "ip.src in {{{PUBLIC_IPV6/64}}}",
			wantErr:    true,
		},
		{
			name:       "Error when IPv4 CIDR placeholder but no IPv4",
			expression: "ip.src in {{{PUBLIC_IPV4/24}}}",
			ipv4:       "",
			ipv6:       "2001:db8::1",
			expected:   "ip.src in {{{PUBLIC_IPV4/24}}}",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ReplacePlaceholders(tt.expression, tt.ipv4, tt.ipv6)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReplacePlaceholders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("ReplacePlaceholders() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestReplacePlaceholdersWithIPv6Prefix_DefaultNetworkPrefix(t *testing.T) {
	result, err := ReplacePlaceholdersWithIPv6Prefix(
		"ip.src in {{{PUBLIC_IPV6_NETWORK}}}",
		"",
		"2001:db8:abcd:1234:5678:90ab:cdef:1234",
		56,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ip.src in {2001:db8:abcd:1200::}" {
		t.Fatalf("unexpected result: %q", result)
	}
}

func TestReplacePlaceholdersWithIPv6Prefix_InvalidPrefix(t *testing.T) {
	_, err := ReplacePlaceholdersWithIPv6Prefix(
		"ip.src in {{{PUBLIC_IPV6_NETWORK}}}",
		"",
		"2001:db8::1",
		129,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
}
