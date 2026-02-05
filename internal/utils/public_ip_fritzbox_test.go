package utils

import "testing"

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
