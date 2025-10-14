package internal

import "os"

// GetEnv returns the environment variable value or a default if unset.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
