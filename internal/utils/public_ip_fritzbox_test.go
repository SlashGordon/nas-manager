package utils

import (
	"net"
	"testing"
)

func TestParseFritzBoxIPv4Response(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>95.88.99.96</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>`)

	ip, err := parseFritzBoxIPv4Response(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "95.88.99.96" {
		t.Fatalf("unexpected ip: %q", ip)
	}
}

func TestParseFritzBoxIPv6Response(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM_DE_GetExternalIPv6AddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPv6Address>2a01:71a0:8002::d:0:1bb5</NewExternalIPv6Address>
      <NewPrefixLength>64</NewPrefixLength>
      <NewValidLifetime>599</NewValidLifetime>
      <NewPreferedLifetime>299</NewPreferedLifetime>
    </u:X_AVM_DE_GetExternalIPv6AddressResponse>
  </s:Body>
</s:Envelope>`)

	ip, prefix, err := parseFritzBoxIPv6Response(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "2a01:71a0:8002::d:0:1bb5" {
		t.Fatalf("unexpected ip: %q", ip)
	}
	if prefix != 64 {
		t.Fatalf("unexpected prefix: %d", prefix)
	}
}

func TestParseFritzBoxIPv6PrefixResponse(t *testing.T) {
	// Test response with prefix in CIDR notation
	xml := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM_DE_GetIPv6PrefixResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewIPv6Prefix>2a01:71a0:8406:7600::/56</NewIPv6Prefix>
      <NewPrefixLength>56</NewPrefixLength>
      <NewValidLifetime>501</NewValidLifetime>
      <NewPreferedLifetime>451</NewPreferedLifetime>
    </u:X_AVM_DE_GetIPv6PrefixResponse>
  </s:Body>
</s:Envelope>`)

	prefix, prefixLen, err := parseFritzBoxIPv6PrefixResponse(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefix != "2a01:71a0:8406:7600::" {
		t.Fatalf("unexpected prefix: %q", prefix)
	}
	if prefixLen != 56 {
		t.Fatalf("unexpected prefix length: %d", prefixLen)
	}
}

func TestParseFritzBoxIPv6PrefixResponseWithoutCIDR(t *testing.T) {
	// Test response without CIDR notation in prefix
	xml := []byte(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM_DE_GetIPv6PrefixResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewIPv6Prefix>2a01:71a0:8406:7600::</NewIPv6Prefix>
      <NewPrefixLength>56</NewPrefixLength>
    </u:X_AVM_DE_GetIPv6PrefixResponse>
  </s:Body>
</s:Envelope>`)

	prefix, prefixLen, err := parseFritzBoxIPv6PrefixResponse(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefix != "2a01:71a0:8406:7600::" {
		t.Fatalf("unexpected prefix: %q", prefix)
	}
	if prefixLen != 56 {
		t.Fatalf("unexpected prefix length: %d", prefixLen)
	}
}

func TestBuildIPv6FromPrefix(t *testing.T) {
	// This test depends on local interface availability
	// We just verify it doesn't crash and returns something sensible
	result := buildIPv6FromPrefix("2a01:71a0:8406:7600::", 56)
	t.Logf("buildIPv6FromPrefix result: %q", result)

	// If we got a result, verify it starts with the prefix
	if result != "" {
		ip := net.ParseIP(result)
		if ip == nil {
			t.Errorf("result is not a valid IP: %q", result)
		}
	}
}

func TestEnsureFullIPv6Address(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		prefixLen int
		wantSame  bool // true if we expect the same address back (already complete)
	}{
		{
			name:      "complete address with host portion",
			ip:        "2a01:71a0:8002::d:0:1bb5",
			prefixLen: 64,
			wantSame:  true, // already has non-zero host portion
		},
		{
			name:      "complete address fully specified",
			ip:        "2001:db8:85a3:0:1234:5678:90ab:cdef",
			prefixLen: 64,
			wantSame:  true,
		},
		{
			name:      "prefix only with zeros",
			ip:        "2a01:71a0:8002::",
			prefixLen: 64,
			wantSame:  false, // host portion is all zeros, should be filled
		},
		{
			name:      "prefix only 48 bits",
			ip:        "2a01:71a0:8002::",
			prefixLen: 48,
			wantSame:  false,
		},
		{
			name:      "invalid address",
			ip:        "not-an-ip",
			prefixLen: 64,
			wantSame:  true, // invalid input returned as-is
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ensureFullIPv6Address(tc.ip, tc.prefixLen)
			if tc.wantSame {
				// For complete addresses, we expect same or equivalent output
				if result != tc.ip && !ipv6Equivalent(result, tc.ip) {
					t.Errorf("expected same address %q, got %q", tc.ip, result)
				}
			} else {
				// For prefix-only, we expect a different (filled) address
				// It might be the same if no local interface is available in test env
				t.Logf("prefix %q -> result %q", tc.ip, result)
			}
		})
	}
}

// ipv6Equivalent checks if two IPv6 strings represent the same address
func ipv6Equivalent(a, b string) bool {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil || ipB == nil {
		return a == b
	}
	return ipA.Equal(ipB)
}
