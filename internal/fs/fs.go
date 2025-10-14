package fs

import (
	"io"
	"os"

	"github.com/spf13/afero"
)

// FS is the global filesystem interface
var FS afero.Fs = afero.NewOsFs()

// ReadFile reads the named file and returns the contents
func ReadFile(filename string) ([]byte, error) {
	return afero.ReadFile(FS, filename)
}

// WriteFile writes data to the named file, creating it if necessary
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	return afero.WriteFile(FS, filename, data, perm)
}

// Open opens the named file for reading
func Open(name string) (afero.File, error) {
	return FS.Open(name)
}

// Create creates or truncates the named file
func Create(name string) (afero.File, error) {
	return FS.Create(name)
}

// Remove removes the named file or directory
func Remove(name string) error {
	return FS.Remove(name)
}

// Rename renames (moves) oldpath to newpath
func Rename(oldname, newname string) error {
	return FS.Rename(oldname, newname)
}

// MkdirAll creates a directory named path, along with any necessary parents
func MkdirAll(path string, perm os.FileMode) error {
	return FS.MkdirAll(path, perm)
}

// Stat returns a FileInfo describing the named file
func Stat(name string) (os.FileInfo, error) {
	return FS.Stat(name)
}

// OpenFile is the generalized open call
func OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return FS.OpenFile(name, flag, perm)
}

// CopyFile copies a file from src to dst with permissions
func CopyFile(src, dst string) error {
	in, err := FS.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := FS.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

func MoveFile(src, dst string) error {
	// Try rename first (atomic if on same FS)
	if err := FS.Rename(src, dst); err == nil {
		return nil
	}

	// Fallback: copy + remove
	if err := CopyFile(src, dst); err != nil {
		return err
	}
	return FS.Remove(src)
}
