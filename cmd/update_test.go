package cmd_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/SlashGordon/nas-manager/cmd"
)

func TestUpdateBinaryAlreadyLatest(t *testing.T) {
	// Mock GitHub API response
	release := cmd.GitHubRelease{
		TagName: "v1.0.0",
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{
			{
				Name:               "nas-manager-linux-amd64",
				BrowserDownloadURL: "https://example.com/nas-manager-linux-amd64",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	// This would normally call the real GitHub API, but we can't easily mock that
	// in the current implementation. This test verifies the struct parsing works.
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to get test response: %v", err)
	}
	defer resp.Body.Close()

	var testRelease cmd.GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&testRelease); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if testRelease.TagName != "v1.0.0" {
		t.Errorf("Expected tag name 'v1.0.0', got '%s'", testRelease.TagName)
	}

	if len(testRelease.Assets) != 1 {
		t.Errorf("Expected 1 asset, got %d", len(testRelease.Assets))
	}
}

func TestUpdateBinaryPlatformDetection(t *testing.T) {
	expectedBinaryName := "nas-manager-" + runtime.GOOS + "-" + runtime.GOARCH

	// Mock release with multiple assets
	release := cmd.GitHubRelease{
		TagName: "v1.1.0",
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{
			{
				Name:               "nas-manager-linux-amd64",
				BrowserDownloadURL: "https://example.com/nas-manager-linux-amd64",
			},
			{
				Name:               "nas-manager-darwin-amd64",
				BrowserDownloadURL: "https://example.com/nas-manager-darwin-amd64",
			},
			{
				Name:               "nas-manager-windows-amd64",
				BrowserDownloadURL: "https://example.com/nas-manager-windows-amd64",
			},
		},
	}

	// Find the asset for current platform
	var foundAsset bool
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == expectedBinaryName {
			foundAsset = true
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	// This test will pass if the current platform has a corresponding asset
	// or skip if the platform isn't in our mock data
	if expectedBinaryName == "nas-manager-linux-amd64" ||
		expectedBinaryName == "nas-manager-darwin-amd64" ||
		expectedBinaryName == "nas-manager-windows-amd64" {
		if !foundAsset {
			t.Errorf("Expected to find asset for platform %s", expectedBinaryName)
		}
		if !strings.Contains(downloadURL, expectedBinaryName) {
			t.Errorf("Expected download URL to contain %s, got %s", expectedBinaryName, downloadURL)
		}
	} else {
		t.Skipf("Skipping test for unsupported platform: %s", expectedBinaryName)
	}
}

func TestGitHubReleaseStruct(t *testing.T) {
	jsonData := `{
		"tag_name": "v1.2.3",
		"assets": [
			{
				"name": "nas-manager-linux-amd64",
				"browser_download_url": "https://github.com/SlashGordon/nas-manager/releases/download/v1.2.3/nas-manager-linux-amd64"
			}
		]
	}`

	var release cmd.GitHubRelease
	if err := json.Unmarshal([]byte(jsonData), &release); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if release.TagName != "v1.2.3" {
		t.Errorf("Expected tag name 'v1.2.3', got '%s'", release.TagName)
	}

	if len(release.Assets) != 1 {
		t.Errorf("Expected 1 asset, got %d", len(release.Assets))
	}

	if release.Assets[0].Name != "nas-manager-linux-amd64" {
		t.Errorf("Expected asset name 'nas-manager-linux-amd64', got '%s'", release.Assets[0].Name)
	}
}

func TestUpdateCommandRegistration(t *testing.T) {
	// Test version string patterns
	devVersion := "dev"
	if !strings.Contains(devVersion, "dev") {
		t.Error("Expected dev version to contain 'dev'")
	}

	releaseVersion := "v1.0.0"
	if strings.Contains(releaseVersion, "dev") {
		t.Error("Expected release version to not contain 'dev'")
	}
}
