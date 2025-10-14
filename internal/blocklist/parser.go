package blocklist

import (
	"net"
	"regexp"
	"strings"
)

// Parser defines how to extract IPs from different blocklist formats
type Parser struct {
	Name    string
	Pattern *regexp.Regexp
	Extract func(matches []string) string
}

// GetParsers returns predefined parsers for common blocklist formats
func GetParsers() map[string]Parser {
	return map[string]Parser{
		"tor_exits": {
			Name:    "Tor Exit Addresses",
			Pattern: regexp.MustCompile(`^ExitAddress\s+(\d+\.\d+\.\d+\.\d+)`),
			Extract: func(matches []string) string { return matches[1] },
		},
		"plain": {
			Name:    "Plain IP/CIDR",
			Pattern: regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s*$`),
			Extract: func(matches []string) string { return matches[1] },
		},
		"spamhaus": {
			Name:    "Spamhaus Format",
			Pattern: regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+/\d+)\s*;`),
			Extract: func(matches []string) string { return matches[1] },
		},
	}
}

// ParseLine extracts IP/CIDR from a line using the appropriate parser
func ParseLine(line, listName string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	parsers := GetParsers()

	// Try specific parser first
	if parser, exists := parsers[listName]; exists {
		if matches := parser.Pattern.FindStringSubmatch(line); matches != nil {
			return parser.Extract(matches)
		}
	}

	// Fallback to plain parser
	if parser := parsers["plain"]; parser.Pattern.MatchString(line) {
		if matches := parser.Pattern.FindStringSubmatch(line); matches != nil {
			return parser.Extract(matches)
		}
	}

	return ""
}

// ValidateIP checks if the extracted string is a valid IP or CIDR
func ValidateIP(ipStr string) bool {
	if strings.Contains(ipStr, "/") {
		_, _, err := net.ParseCIDR(ipStr)
		return err == nil
	}
	return net.ParseIP(ipStr) != nil
}
