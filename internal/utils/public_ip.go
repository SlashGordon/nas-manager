package utils

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ipv4Services = []string{
		"https://api.ipify.org",
		"https://api4.my-ip.io/ip",
		"https://v4.ident.me",
	}
	ipv6Services = []string{
		"https://api6.ipify.org",
		"https://api6.my-ip.io/ip",
		"https://v6.ident.me",
	}
)

func fetchPublicIP(ctx context.Context, services []string) (string, error) {
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

// GetPublicIPv4 fetches the current public IPv4 address.
// It queries multiple providers to increase reliability and returns an empty
// string if the address cannot be determined.
func GetPublicIPv4(ctx context.Context) (string, error) {
	return fetchPublicIP(ctx, ipv4Services)
}

// GetPublicIPv6 fetches the current public IPv6 address.
// It queries multiple providers to increase reliability and returns an empty
// string if the address cannot be determined.
func GetPublicIPv6(ctx context.Context) (string, error) {
	return fetchPublicIP(ctx, ipv6Services)
}

// GetPublicIP fetches the current public IPv4 and IPv6 addresses.
// It queries multiple providers to increase reliability and returns
// empty strings if an address cannot be determined.
func GetPublicIP(ctx context.Context) (ipv4, ipv6 string, err error) {
	v4, _ := fetchPublicIP(ctx, ipv4Services)
	v6, _ := fetchPublicIP(ctx, ipv6Services)
	return v4, v6, nil
}
