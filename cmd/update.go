package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/i18n"

	"github.com/spf13/cobra"
)

var updateManagerCmd = &cobra.Command{
	Use:   "update",
	Short: i18n.T(i18n.CmdUpdateShort),
	Run: func(_ *cobra.Command, _ []string) {
		if err := updateBinary(); err != nil {
			log.Errorf(i18n.T(i18n.UpdateFailed), err)
			os.Exit(1)
		}
	},
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func updateBinary() error {
	log.Info(i18n.T(i18n.UpdateChecking))

	release, err := getLatestRelease()
	if err != nil {
		return err
	}

	// Check if update is needed
	if release.TagName == Version {
		log.Infof(i18n.T(i18n.UpdateLatest), Version)
		return nil
	}

	log.Infof(i18n.T(i18n.UpdateAvailable), release.TagName, Version)

	return downloadAndInstall(release)
}

func getLatestRelease() (*GitHubRelease, error) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://api.github.com/repos/SlashGordon/nas-manager/releases/latest",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	var release GitHubRelease
	if decodeErr := json.NewDecoder(resp.Body).Decode(&release); decodeErr != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", decodeErr)
	}

	return &release, nil
}

func downloadAndInstall(release *GitHubRelease) error {
	binaryName := fmt.Sprintf("nas-manager-%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL := findAssetURL(release, binaryName)

	if downloadURL == "" {
		return fmt.Errorf("no binary found for platform %s-%s", runtime.GOOS, runtime.GOARCH)
	}

	log.Infof(i18n.T(i18n.UpdateDownloading), binaryName)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	return installBinary(resp.Body, release)
}

func findAssetURL(release *GitHubRelease, binaryName string) string {
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func installBinary(body io.Reader, release *GitHubRelease) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	tmpFile := execPath + ".tmp"
	out, err := fs.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, body); err != nil {
		fs.Remove(tmpFile)
		return fmt.Errorf("failed to write update: %w", err)
	}

	out.Close()

	if err := os.Chmod(tmpFile, constants.FilePermission0755); err != nil {
		fs.Remove(tmpFile)
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	return replaceBinary(tmpFile, execPath, release)
}

func replaceBinary(tmpFile, execPath string, release *GitHubRelease) error {
	if runtime.GOOS == "windows" {
		oldFile := execPath + ".old"
		if renameErr := fs.Rename(execPath, oldFile); renameErr != nil {
			fs.Remove(tmpFile)
			return fmt.Errorf("failed to backup current binary: %w", renameErr)
		}
		if renameErr := fs.Rename(tmpFile, execPath); renameErr != nil {
			fs.Rename(oldFile, execPath)
			return fmt.Errorf("failed to replace binary: %w", renameErr)
		}
		fs.Remove(oldFile)
	} else {
		if moveErr := fs.MoveFile(tmpFile, execPath); moveErr != nil {
			fs.Remove(tmpFile)
			return fmt.Errorf("failed to replace binary: %w", moveErr)
		}
	}

	log.Infof(i18n.T(i18n.UpdateSuccess), release.TagName)
	log.Info(i18n.T(i18n.UpdateRestart))

	return nil
}

func init() {
	// Only add update command if not running in development
	if !strings.Contains(Version, "dev") {
		rootCmd.AddCommand(updateManagerCmd)
	}
}
