package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile_SetsMissingValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	content := "# comment\nFOO=bar\nexport BAZ=qux\nQUOTED=\"hello\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp env: %v", err)
	}

	os.Unsetenv("FOO")
	os.Unsetenv("BAZ")
	os.Unsetenv("QUOTED")
	if err := loadEnvFile(path, false); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}

	if got := os.Getenv("FOO"); got != "bar" {
		t.Fatalf("FOO=%q", got)
	}
	if got := os.Getenv("BAZ"); got != "qux" {
		t.Fatalf("BAZ=%q", got)
	}
	if got := os.Getenv("QUOTED"); got != "hello" {
		t.Fatalf("QUOTED=%q", got)
	}
}

func TestLoadEnvFile_DoesNotOverrideByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	content := "FOO=fromfile\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp env: %v", err)
	}

	t.Setenv("FOO", "fromenv")
	if err := loadEnvFile(path, false); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("FOO"); got != "fromenv" {
		t.Fatalf("FOO=%q", got)
	}
}

func TestLoadEnvFile_OverrideEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	content := "FOO=fromfile\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp env: %v", err)
	}

	t.Setenv("FOO", "fromenv")
	if err := loadEnvFile(path, true); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("FOO"); got != "fromfile" {
		t.Fatalf("FOO=%q", got)
	}
}
