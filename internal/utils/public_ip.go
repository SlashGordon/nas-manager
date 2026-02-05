package utils

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

// PublicIPProvider is the minimal interface for IP providers.
// Providers can implement one or both of the family-specific interfaces below.
type PublicIPProvider interface {
	Name() string
}

type PublicIPv4Provider interface {
	PublicIPProvider
	GetPublicIPv4(ctx context.Context) (string, error)
}

type PublicIPv6Provider interface {
	PublicIPProvider
	GetPublicIPv6(ctx context.Context) (string, error)
}

// PublicIPResolver tries multiple providers and returns the first non-empty value.
// This keeps the business logic (retry order, fallbacks) in one place.
type PublicIPResolver struct {
	Providers []PublicIPProvider
}

func NewPublicIPResolver(providers ...PublicIPProvider) *PublicIPResolver {
	return &PublicIPResolver{Providers: providers}
}

func DefaultPublicIPResolver() *PublicIPResolver {
	return PublicIPResolverFromEnv()
}

// PublicIPResolverFromEnv builds a resolver based on environment variables.
//
// Supported variables:
//   - NAS_MANAGER_PUBLIC_IP_PROVIDERS: comma-separated provider names in order.
//     Supported: fritzbox-soap, external-http
//     Default: fritzbox-soap,external-http
//   - NAS_MANAGER_FRITZBOX_WANIPCONN_URL: overrides the FritzBox WANIPConn1 control URL.
//     Default: http://fritz.box:49000/igdupnp/control/WANIPConn1
//   - NAS_MANAGER_FRITZBOX_TIMEOUT: FritzBox SOAP timeout (Go duration, e.g. 2s, 500ms).
//     Default: 3s
func PublicIPResolverFromEnv() *PublicIPResolver {
	providerList := strings.TrimSpace(os.Getenv("NAS_MANAGER_PUBLIC_IP_PROVIDERS"))
	if providerList == "" {
		providerList = "fritzbox-soap,external-http"
	}

	fritzURL := strings.TrimSpace(os.Getenv("NAS_MANAGER_FRITZBOX_WANIPCONN_URL"))
	if fritzURL == "" {
		fritzURL = fritzBoxWANIPConnectionURL
	}
	fritzTimeout := 3 * time.Second
	if raw := strings.TrimSpace(os.Getenv("NAS_MANAGER_FRITZBOX_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			fritzTimeout = d
		}
	}

	var providers []PublicIPProvider
	for _, raw := range strings.Split(providerList, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "fritzbox-soap":
			p := NewFritzBoxSOAPProvider()
			p.URL = fritzURL
			p.Timeout = fritzTimeout
			providers = append(providers, p)
		case "external-http":
			providers = append(providers, NewExternalHTTPProvider())
		default:
			// Unknown provider name: ignore (keeps config forward-compatible).
		}
	}

	if len(providers) == 0 {
		providers = []PublicIPProvider{
			NewFritzBoxSOAPProvider(),
			NewExternalHTTPProvider(),
		}
	}

	return NewPublicIPResolver(providers...)
}

func (r *PublicIPResolver) firstProviderValue(ctx context.Context, family string) (string, error) {
	var errs []error
	for _, p := range r.Providers {
		var (
			value string
			err   error
		)
		switch family {
		case "ipv4":
			provider, ok := p.(PublicIPv4Provider)
			if !ok {
				continue
			}
			value, err = provider.GetPublicIPv4(ctx)
		case "ipv6":
			provider, ok := p.(PublicIPv6Provider)
			if !ok {
				continue
			}
			value, err = provider.GetPublicIPv6(ctx)
		default:
			return "", errors.New("unknown IP family")
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.Join(errs...)
}

func (r *PublicIPResolver) GetPublicIPv4(ctx context.Context) (string, error) {
	return r.firstProviderValue(ctx, "ipv4")
}

func (r *PublicIPResolver) GetPublicIPv6(ctx context.Context) (string, error) {
	return r.firstProviderValue(ctx, "ipv6")
}

// GetPublicIPv4 fetches the current public IPv4 address.
// It queries multiple providers to increase reliability and returns an empty
// string if the address cannot be determined.
func GetPublicIPv4(ctx context.Context) (string, error) {
	value, err := DefaultPublicIPResolver().GetPublicIPv4(ctx)
	if err != nil {
		return "", nil
	}
	return value, nil
}

// GetPublicIPv6 fetches the current public IPv6 address.
// It queries multiple providers to increase reliability and returns an empty
// string if the address cannot be determined.
func GetPublicIPv6(ctx context.Context) (string, error) {
	value, err := DefaultPublicIPResolver().GetPublicIPv6(ctx)
	if err != nil {
		return "", nil
	}
	return value, nil
}

// GetPublicIP fetches the current public IPv4 and IPv6 addresses.
// It queries multiple providers to increase reliability and returns
// empty strings if an address cannot be determined.
func GetPublicIP(ctx context.Context) (ipv4, ipv6 string, err error) {
	v4, _ := GetPublicIPv4(ctx)
	v6, _ := GetPublicIPv6(ctx)
	return v4, v6, nil
}
