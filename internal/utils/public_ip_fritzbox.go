package utils

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const fritzBoxWANIPConnectionURL = "http://fritz.box:49000/igdupnp/control/WANIPConn1"

type FritzBoxSOAPProvider struct {
	URL     string
	Timeout time.Duration
}

func NewFritzBoxSOAPProvider() *FritzBoxSOAPProvider {
	return &FritzBoxSOAPProvider{
		URL:     fritzBoxWANIPConnectionURL,
		Timeout: 3 * time.Second,
	}
}

func (p *FritzBoxSOAPProvider) Name() string { return "fritzbox-soap" }

func (p *FritzBoxSOAPProvider) GetPublicIPv4(ctx context.Context) (string, error) {
	resp, err := fritzBoxSOAPRequest(ctx,
		p.URL,
		p.Timeout,
		"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress",
		fritzBoxSOAPBodyGetExternalIPAddress,
	)
	if err != nil {
		return "", err
	}
	return parseFritzBoxIPv4Response(resp)
}

func (p *FritzBoxSOAPProvider) GetPublicIPv6(ctx context.Context) (string, error) {
	// First, get the delegated IPv6 prefix (this is what LAN devices use)
	resp, err := fritzBoxSOAPRequest(ctx,
		p.URL,
		p.Timeout,
		"urn:schemas-upnp-org:service:WANIPConnection:1#X_AVM_DE_GetIPv6Prefix",
		fritzBoxSOAPBodyGetIPv6Prefix,
	)
	if err == nil {
		prefix, prefixLen, parseErr := parseFritzBoxIPv6PrefixResponse(resp)
		if parseErr == nil && prefix != "" && prefixLen > 0 {
			// Combine the delegated prefix with local interface ID
			fullIP := buildIPv6FromPrefix(prefix, prefixLen)
			if fullIP != "" {
				return fullIP, nil
			}
		}
	}

	// Fallback: get the router's external IPv6 address
	resp, err = fritzBoxSOAPRequest(ctx,
		p.URL,
		p.Timeout,
		"urn:schemas-upnp-org:service:WANIPConnection:1#X_AVM_DE_GetExternalIPv6Address",
		fritzBoxSOAPBodyGetExternalIPv6Address,
	)
	if err != nil {
		return "", err
	}
	ip, prefixLen, err := parseFritzBoxIPv6Response(resp)
	if err != nil {
		return "", err
	}
	// If FritzBox returns only a prefix (host portion is zeros), try to build a full address
	if ip != "" && prefixLen > 0 && prefixLen < 128 {
		ip = ensureFullIPv6Address(ip, prefixLen)
	}
	return ip, nil
}

const fritzBoxSOAPBodyGetExternalIPAddress = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1" />
  </s:Body>
</s:Envelope>
`

const fritzBoxSOAPBodyGetExternalIPv6Address = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM_DE_GetExternalIPv6Address xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1" />
  </s:Body>
</s:Envelope>
`

const fritzBoxSOAPBodyGetIPv6Prefix = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM_DE_GetIPv6Prefix xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1" />
  </s:Body>
</s:Envelope>
`

func fritzBoxSOAPRequest(ctx context.Context, url string, timeout time.Duration, soapAction, body string) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SoapAction", soapAction)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fritzbox SOAP request failed: HTTP %d", resp.StatusCode)
	}
	return b, nil
}

func parseFritzBoxIPv4Response(data []byte) (string, error) {
	value, err := extractXMLLocalNameText(data, "NewExternalIPAddress")
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 address from fritzbox: %q", value)
	}
	return value, nil
}

func parseFritzBoxIPv6Response(data []byte) (ip string, prefixLen int, err error) {
	ipStr, err := extractXMLLocalNameText(data, "NewExternalIPv6Address")
	if err != nil {
		return "", 0, err
	}
	ipStr = strings.TrimSpace(ipStr)
	if ipStr != "" {
		parsed := net.ParseIP(ipStr)
		if parsed == nil || parsed.To4() != nil {
			return "", 0, fmt.Errorf("invalid IPv6 address from fritzbox: %q", ipStr)
		}
	}

	prefixStr, err := extractXMLLocalNameText(data, "NewPrefixLength")
	if err != nil {
		return "", 0, err
	}
	prefixStr = strings.TrimSpace(prefixStr)
	if prefixStr != "" {
		p, convErr := strconv.Atoi(prefixStr)
		if convErr != nil {
			return "", 0, fmt.Errorf("invalid IPv6 prefix length from fritzbox: %q", prefixStr)
		}
		if p < 0 || p > 128 {
			return "", 0, fmt.Errorf("invalid IPv6 prefix length from fritzbox: %d", p)
		}
		prefixLen = p
	}

	return ipStr, prefixLen, nil
}

// parseFritzBoxIPv6PrefixResponse parses the X_AVM_DE_GetIPv6Prefix response.
// This returns the delegated prefix (e.g., 2a01:71a0:8406:7600::/56) that LAN devices use.
func parseFritzBoxIPv6PrefixResponse(data []byte) (prefix string, prefixLen int, err error) {
	prefixStr, err := extractXMLLocalNameText(data, "NewIPv6Prefix")
	if err != nil {
		return "", 0, err
	}
	prefixStr = strings.TrimSpace(prefixStr)
	if prefixStr == "" {
		return "", 0, nil
	}

	// The prefix might be in CIDR notation (2a01:71a0:8406:7600::/56) or just the address
	if strings.Contains(prefixStr, "/") {
		parts := strings.SplitN(prefixStr, "/", 2)
		prefixStr = parts[0]
		if len(parts) == 2 {
			p, convErr := strconv.Atoi(parts[1])
			if convErr == nil && p >= 0 && p <= 128 {
				prefixLen = p
			}
		}
	}

	parsed := net.ParseIP(prefixStr)
	if parsed == nil || parsed.To4() != nil {
		return "", 0, fmt.Errorf("invalid IPv6 prefix from fritzbox: %q", prefixStr)
	}

	// Also check for separate PrefixLength field if not in CIDR notation
	if prefixLen == 0 {
		lenStr, _ := extractXMLLocalNameText(data, "NewPrefixLength")
		lenStr = strings.TrimSpace(lenStr)
		if lenStr != "" {
			p, convErr := strconv.Atoi(lenStr)
			if convErr == nil && p >= 0 && p <= 128 {
				prefixLen = p
			}
		}
	}

	return prefixStr, prefixLen, nil
}

// buildIPv6FromPrefix combines an IPv6 prefix with the local interface ID to create a full address.
func buildIPv6FromPrefix(prefix string, prefixLen int) string {
	prefixIP := net.ParseIP(prefix)
	if prefixIP == nil {
		return ""
	}
	prefix16 := prefixIP.To16()
	if prefix16 == nil {
		return ""
	}

	interfaceID := getLocalIPv6InterfaceID(prefixLen)
	if interfaceID == nil {
		return ""
	}

	// Combine prefix with interface ID
	mask := net.CIDRMask(prefixLen, 128)
	result := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		result[i] = (prefix16[i] & mask[i]) | (interfaceID[i] & ^mask[i])
	}

	return result.String()
}

// ensureFullIPv6Address checks if the given IPv6 address has a zeroed host portion
// (indicating it's just a prefix). If so, it attempts to combine it with the local
// interface's IPv6 address suffix to create a complete address for Cloudflare.
func ensureFullIPv6Address(ip string, prefixLen int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	ip16 := parsed.To16()
	if ip16 == nil {
		return ip
	}

	// Check if the host portion (bits after prefixLen) is all zeros
	mask := net.CIDRMask(prefixLen, 128)
	hostAllZeros := true
	for i := 0; i < 16; i++ {
		hostBits := ip16[i] & ^mask[i]
		if hostBits != 0 {
			hostAllZeros = false
			break
		}
	}

	// If host portion has non-zero bits, the address is already complete
	if !hostAllZeros {
		return ip
	}

	// Host portion is all zeros - try to get interface ID from local IPv6 addresses
	interfaceID := getLocalIPv6InterfaceID(prefixLen)
	if interfaceID == nil {
		return ip // Can't get local interface ID, return as-is
	}

	// Combine the prefix with the local interface ID
	for i := 0; i < 16; i++ {
		ip16[i] = (ip16[i] & mask[i]) | (interfaceID[i] & ^mask[i])
	}

	return ip16.String()
}

// getLocalIPv6InterfaceID returns the interface identifier portion from a local
// global IPv6 address that can be used to complete a prefix-only address.
func getLocalIPv6InterfaceID(prefixLen int) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To16()
			if ip == nil || ip.To4() != nil {
				continue // Skip non-IPv6
			}
			// Skip link-local (fe80::/10) and unique local (fc00::/7) addresses
			if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
				continue
			}
			if (ip[0] & 0xfe) == 0xfc {
				continue
			}
			// Found a global IPv6 address - return it for interface ID extraction
			return ip
		}
	}
	return nil
}

func extractXMLLocalNameText(data []byte, localName string) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != localName {
			continue
		}
		var v string
		if err := dec.DecodeElement(&v, &start); err != nil {
			return "", err
		}
		return v, nil
	}
}
