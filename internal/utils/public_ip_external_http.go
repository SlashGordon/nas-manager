package utils

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	externalIPv4Services = []string{
		"https://api.ipify.org",
		"https://api4.my-ip.io/ip",
		"https://v4.ident.me",
	}
	externalIPv6Services = []string{
		"https://api6.ipify.org",
		"https://api6.my-ip.io/ip",
		"https://v6.ident.me",
	}
)

func fetchPublicIPFromServices(ctx context.Context, services []string) (string, error) {
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
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
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

type ExternalHTTPProvider struct{}

func NewExternalHTTPProvider() *ExternalHTTPProvider { return &ExternalHTTPProvider{} }

func (p *ExternalHTTPProvider) Name() string { return "external-http" }

func (p *ExternalHTTPProvider) GetPublicIPv4(ctx context.Context) (string, error) {
	return fetchPublicIPFromServices(ctx, externalIPv4Services)
}

func (p *ExternalHTTPProvider) GetPublicIPv6(ctx context.Context) (string, error) {
	return fetchPublicIPFromServices(ctx, externalIPv6Services)
}
