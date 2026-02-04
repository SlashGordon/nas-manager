package security

import (
	"context"
	"testing"
)

func TestResolvePublicIPs_OverridesSkipFetcher(t *testing.T) {
	fetcher := func(_ context.Context) (string, string, error) {
		t.Fatalf("fetcher should not be called when overrides are provided")
		return "", "", nil
	}

	ctx := context.Background()

	ipv4, ipv6, err := resolvePublicIPs(ctx, "203.0.113.5", "", fetcher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != "203.0.113.5" || ipv6 != "" {
		t.Fatalf("unexpected result: ipv4=%q ipv6=%q", ipv4, ipv6)
	}

	ipv4, ipv6, err = resolvePublicIPs(ctx, "", "2001:db8::1", fetcher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != "" || ipv6 != "2001:db8::1" {
		t.Fatalf("unexpected result: ipv4=%q ipv6=%q", ipv4, ipv6)
	}

	ipv4, ipv6, err = resolvePublicIPs(ctx, "203.0.113.10", "2001:db8::2", fetcher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ipv4 != "203.0.113.10" || ipv6 != "2001:db8::2" {
		t.Fatalf("unexpected result: ipv4=%q ipv6=%q", ipv4, ipv6)
	}
}

func TestResolvePublicIPs_Validation(t *testing.T) {
	ctx := context.Background()

	_, _, err := resolvePublicIPs(ctx, "not-an-ip", "", func(context.Context) (string, string, error) { return "", "", nil })
	if err == nil {
		t.Fatalf("expected error for invalid IPv4 override")
	}

	_, _, err = resolvePublicIPs(ctx, "", "203.0.113.1", func(context.Context) (string, string, error) { return "", "", nil })
	if err == nil {
		t.Fatalf("expected error for invalid IPv6 override")
	}
}

func TestResolvePublicIPs_FetcherUsedWhenNoOverrides(t *testing.T) {
	ctx := context.Background()

	fetcherCalled := false
	fetcher := func(_ context.Context) (string, string, error) {
		fetcherCalled = true
		return "198.51.100.7", "2001:db8::7", nil
	}

	ipv4, ipv6, err := resolvePublicIPs(ctx, "", "", fetcher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fetcherCalled {
		t.Fatalf("expected fetcher to be called")
	}
	if ipv4 != "198.51.100.7" || ipv6 != "2001:db8::7" {
		t.Fatalf("unexpected result: ipv4=%q ipv6=%q", ipv4, ipv6)
	}
}
