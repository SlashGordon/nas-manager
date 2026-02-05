package utils

import (
	"os"
	"testing"
)

func TestPublicIPResolverFromEnv_ProviderOrder(t *testing.T) {
	oldProviders := os.Getenv("NAS_MANAGER_PUBLIC_IP_PROVIDERS")
	oldURL := os.Getenv("NAS_MANAGER_FRITZBOX_WANIPCONN_URL")
	oldTimeout := os.Getenv("NAS_MANAGER_FRITZBOX_TIMEOUT")
	t.Cleanup(func() {
		_ = os.Setenv("NAS_MANAGER_PUBLIC_IP_PROVIDERS", oldProviders)
		_ = os.Setenv("NAS_MANAGER_FRITZBOX_WANIPCONN_URL", oldURL)
		_ = os.Setenv("NAS_MANAGER_FRITZBOX_TIMEOUT", oldTimeout)
	})

	_ = os.Setenv("NAS_MANAGER_PUBLIC_IP_PROVIDERS", "external-http,fritzbox-soap")
	_ = os.Setenv("NAS_MANAGER_FRITZBOX_WANIPCONN_URL", "http://example.invalid")
	_ = os.Setenv("NAS_MANAGER_FRITZBOX_TIMEOUT", "1500ms")

	r := PublicIPResolverFromEnv()
	if len(r.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(r.Providers))
	}
	if r.Providers[0].Name() != "external-http" {
		t.Fatalf("unexpected provider[0]: %q", r.Providers[0].Name())
	}
	if r.Providers[1].Name() != "fritzbox-soap" {
		t.Fatalf("unexpected provider[1]: %q", r.Providers[1].Name())
	}

	fb, ok := r.Providers[1].(*FritzBoxSOAPProvider)
	if !ok {
		t.Fatalf("expected fritzbox provider to be *FritzBoxSOAPProvider")
	}
	if fb.URL != "http://example.invalid" {
		t.Fatalf("unexpected fritzbox URL: %q", fb.URL)
	}
	if fb.Timeout.String() != "1.5s" {
		t.Fatalf("unexpected fritzbox timeout: %s", fb.Timeout)
	}
}
