package security_test

import (
	"testing"

	"github.com/SlashGordon/nas-manager/cmd/security"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/logger"
)

func TestExtractAndMergeIPs(t *testing.T) {
	// Create test files
	testFile1 := "/tmp/test_blocklist1.txt"
	testFile2 := "/tmp/test_blocklist2.txt"

	// Test data with duplicates
	data1 := `# Comment
192.168.1.1
10.0.0.1
192.168.1.1
203.0.113.1`

	data2 := `192.168.1.1
198.51.100.1
10.0.0.1
# Another comment
172.16.0.1`

	// Write test files
	fs.WriteFile(testFile1, []byte(data1), 0644)
	fs.WriteFile(testFile2, []byte(data2), 0644)
	defer fs.Remove(testFile1)
	defer fs.Remove(testFile2)

	// Test blocklists with local files
	lists := []security.Blocklist{
		{"test1", testFile1},
		{"test2", testFile2},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	ips, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("extractAndMergeIPs failed: %v", err)
		return
	}

	// Should have 5 unique IPs (duplicates removed)
	expectedCount := 5
	if len(ips) != expectedCount {
		t.Errorf("Expected %d unique IPs, got %d", expectedCount, len(ips))
	}

	// Check that all expected IPs are present
	expectedIPs := map[string]bool{
		"192.168.1.1":  false,
		"10.0.0.1":     false,
		"203.0.113.1":  false,
		"198.51.100.1": false,
		"172.16.0.1":   false,
	}

	for _, ip := range ips {
		if _, exists := expectedIPs[ip]; exists {
			expectedIPs[ip] = true
		} else {
			t.Errorf("Unexpected IP found: %s", ip)
		}
	}

	// Verify all expected IPs were found
	for ip, found := range expectedIPs {
		if !found {
			t.Errorf("Expected IP not found: %s", ip)
		}
	}
}

func TestTorExitAddressExtraction(t *testing.T) {
	// Create test Tor exit addresses file
	testFile := "/tmp/test_tor_exits.txt"
	torData := `# Tor exit addresses
ExitAddress 192.168.1.1 2023-01-01 12:00:00
ExitAddress 10.0.0.1 2023-01-01 12:01:00
Invalid line
ExitAddress 203.0.113.1 2023-01-01 12:02:00`

	fs.WriteFile(testFile, []byte(torData), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"tor_exits", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	ips, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("extractAndMergeIPs failed: %v", err)
		return
	}

	expectedCount := 3
	if len(ips) != expectedCount {
		t.Errorf("Expected %d Tor exit IPs, got %d", expectedCount, len(ips))
	}
}

func TestLocalFileNotFound(t *testing.T) {
	lists := []security.Blocklist{
		{"nonexistent", "/tmp/nonexistent_file.txt"},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	ips, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("extractAndMergeIPs should not fail for missing files: %v", err)
		return
	}

	// Should return empty list when file not found
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for missing file, got %d", len(ips))
	}
}

func TestLocalIPFiltering(t *testing.T) {
	testFile := "/tmp/test_local_ips.txt"
	data := `# Test data with local and public IPs
192.168.1.1
10.0.0.1
172.16.0.1
8.8.8.8
1.1.1.1
127.0.0.1
169.254.1.1`

	fs.WriteFile(testFile, []byte(data), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"test_local", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	// Test with local IP filtering enabled
	ips, err := security.ExtractAndMergeIPs(lists, false, true)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	// Should only have public IPs (8.8.8.8, 1.1.1.1)
	expectedCount := 2
	if len(ips) != expectedCount {
		t.Errorf("Expected %d public IPs, got %d", expectedCount, len(ips))
	}

	// Verify only public IPs are present
	publicIPs := map[string]bool{"8.8.8.8": false, "1.1.1.1": false}
	for _, ip := range ips {
		if _, exists := publicIPs[ip]; exists {
			publicIPs[ip] = true
		} else {
			t.Errorf("Unexpected IP found (should be filtered): %s", ip)
		}
	}

	// Test with local IP filtering disabled
	ips2, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	// Should have all IPs (7 total)
	expectedCount2 := 7
	if len(ips2) != expectedCount2 {
		t.Errorf("Expected %d total IPs, got %d", expectedCount2, len(ips2))
	}
}

func TestCloudflareIPFiltering(t *testing.T) {
	testFile := "/tmp/test_cf_ips.txt"
	// Using known Cloudflare IP ranges for testing
	data := `# Test data with Cloudflare and other IPs
104.16.0.1
172.64.0.1
8.8.8.8
1.1.1.1
203.0.113.1`

	fs.WriteFile(testFile, []byte(data), 0644)
	defer fs.Remove(testFile)

	lists := []security.Blocklist{
		{"test_cf", testFile},
	}

	// Set up logger
	log := logger.NewCLILogger()
	security.SetLogger(log)

	// Test with Cloudflare filtering enabled (may not filter if CF ranges not fetched)
	ips, err := security.ExtractAndMergeIPs(lists, true, false)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	// Should have at least some IPs (exact count depends on CF range availability)
	if len(ips) == 0 {
		t.Errorf("Expected some IPs, got 0")
	}

	// Test with Cloudflare filtering disabled
	ips2, err := security.ExtractAndMergeIPs(lists, false, false)
	if err != nil {
		t.Errorf("ExtractAndMergeIPs failed: %v", err)
		return
	}

	// Should have all 5 IPs
	expectedCount := 5
	if len(ips2) != expectedCount {
		t.Errorf("Expected %d total IPs, got %d", expectedCount, len(ips2))
	}
}
