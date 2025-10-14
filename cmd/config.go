package cmd

import "os"

// GetEnv returns environment variable value or default
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetDDNSConfig returns DDNS configuration
func GetDDNSConfig() DDNSConfig {
	return getDDNSConfig()
}

// GetAcmeConfig returns ACME configuration
func GetAcmeConfig() AcmeConfig {
	return getAcmeConfig()
}
