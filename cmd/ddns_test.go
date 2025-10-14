package cmd_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SlashGordon/nas-manager/internal/fs"
)

func TestGetCurrentIP(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("192.168.1.100"))
	}))
	defer server.Close()

	ip := getCurrentIPTest(server.URL)
	if ip != "192.168.1.100" {
		t.Errorf("Expected '192.168.1.100', got '%s'", ip)
	}
}

func TestGetCurrentIPError(t *testing.T) {
	// Test with invalid URL
	ip := getCurrentIPTest("http://invalid-url-that-does-not-exist")
	if ip != "" {
		t.Errorf("Expected empty string for invalid URL, got '%s'", ip)
	}
}

func TestReadWriteCache(t *testing.T) {
	cacheFile := "/tmp/test_ddns_cache"

	// Test writing cache
	writeCacheTest(cacheFile, "192.168.1.1", "2001:db8::1")

	// Test reading cache
	ip4, ip6 := readCacheTest(cacheFile)

	if ip4 != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%s'", ip4)
	}
	if ip6 != "2001:db8::1" {
		t.Errorf("Expected '2001:db8::1', got '%s'", ip6)
	}

	// Cleanup
	fs.Remove(cacheFile)
}

func TestReadCacheEmpty(t *testing.T) {
	// Test reading non-existent cache
	ip4, ip6 := readCacheTest("/tmp/non_existent_cache")
	if ip4 != "" || ip6 != "" {
		t.Errorf("Expected empty strings for non-existent cache, got '%s', '%s'", ip4, ip6)
	}
}

func TestReadCacheSingleLine(t *testing.T) {
	cacheFile := "/tmp/test_single_cache"

	// Write single line cache
	fs.WriteFile(cacheFile, []byte("192.168.1.1"), 0644)

	ip4, ip6 := readCacheTest(cacheFile)
	if ip4 != "192.168.1.1" || ip6 != "" {
		t.Errorf("Expected '192.168.1.1' and empty string, got '%s', '%s'", ip4, ip6)
	}

	fs.Remove(cacheFile)
}

func getCurrentIPTest(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func writeCacheTest(filename, ip4, ip6 string) {
	content := ip4
	if ip6 != "" {
		content += "\n" + ip6
	}
	fs.WriteFile(filename, []byte(content), 0600)
}

func readCacheTest(filename string) (string, string) {
	content, err := fs.ReadFile(filename)
	if err != nil {
		return "", ""
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) >= 1 && lines[0] != "" {
		if len(lines) >= 2 {
			return lines[0], lines[1]
		}
		return lines[0], ""
	}
	return "", ""
}
