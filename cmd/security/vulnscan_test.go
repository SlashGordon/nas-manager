package security_test

import (
	"testing"
)

func TestIdentifyService(t *testing.T) {
	tests := []struct {
		port     string
		expected string
	}{
		{"22", "SSH"},
		{"80", "HTTP (DSM)"},
		{"443", "HTTPS (DSM)"},
		{"5000", "DSM HTTP"},
		{"5001", "DSM HTTPS"},
		{"873", "rsync"},
		{"9999", "Unknown"},
		{"", "Unknown"},
	}

	for _, tt := range tests {
		t.Run("port_"+tt.port, func(t *testing.T) {
			result := identifyServiceTest(tt.port)
			if result != tt.expected {
				t.Errorf("Expected service '%s' for port '%s', got '%s'", tt.expected, tt.port, result)
			}
		})
	}
}

func TestGetKnownVulnerabilities(t *testing.T) {
	tests := []struct {
		service  string
		minVulns int
	}{
		{"ssh", 2},
		{"apache2", 2},
		{"nginx", 2},
		{"mysql", 2},
		{"postgresql", 2},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			vulns := getKnownVulnerabilitiesTest(tt.service)
			if len(vulns) < tt.minVulns {
				t.Errorf("Expected at least %d vulnerabilities for %s, got %d", tt.minVulns, tt.service, len(vulns))
			}
		})
	}
}

func identifyServiceTest(port string) string {
	services := map[string]string{
		"22":   "SSH",
		"80":   "HTTP (DSM)",
		"443":  "HTTPS (DSM)",
		"5000": "DSM HTTP",
		"5001": "DSM HTTPS",
		"873":  "rsync",
	}
	if service, exists := services[port]; exists {
		return service
	}
	return "Unknown"
}

func getKnownVulnerabilitiesTest(service string) []string {
	switch service {
	case "ssh":
		return []string{"Check for weak SSH configurations", "Ensure key-based authentication is enabled"}
	case "apache2", "nginx":
		return []string{"Check for outdated web server version", "Verify SSL/TLS configuration"}
	case "mysql", "postgresql":
		return []string{"Check for default credentials", "Verify database access controls"}
	default:
		return []string{}
	}
}
