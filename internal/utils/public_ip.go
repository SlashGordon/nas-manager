package utils

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP fetches the current public IPv4 and IPv6 addresses.
// It queries multiple providers to increase reliability and returns
// empty strings if an address cannot be determined.
func GetPublicIP(ctx context.Context) (ipv4, ipv6 string, err error) {
	// Helper to fetch from a list of endpoints
	fetch := func(services []string) (string, error) {
		client := &http.Client{Timeout: 10 * time.Second}
		for _, service := range services {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, service, nil)
			if reqErr != nil {
				continue
			}
			resp, doErr := client.Do(req)
			if doErr != nil {
				continue
			}
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if ip != "" {
				return ip, nil
			}
		}
		return "", nil
	}

	// IPv4 providers
	ipv4Services := []string{
		"https://api.ipify.org",
		"https://api4.my-ip.io/ip",
		"https://v4.ident.me",
	}
	// IPv6 providers
	ipv6Services := []string{
		"https://api6.ipify.org",
		"https://api6.my-ip.io/ip",
		"https://v6.ident.me",
	}

	v4, _ := fetch(ipv4Services)
	v6, _ := fetch(ipv6Services)
	return v4, v6, nil
}
