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
	resp, err := fritzBoxSOAPRequest(ctx,
		p.URL,
		p.Timeout,
		"urn:schemas-upnp-org:service:WANIPConnection:1#X_AVM_DE_GetExternalIPv6Address",
		fritzBoxSOAPBodyGetExternalIPv6Address,
	)
	if err != nil {
		return "", err
	}
	ip, _, err := parseFritzBoxIPv6Response(resp)
	if err != nil {
		return "", err
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
