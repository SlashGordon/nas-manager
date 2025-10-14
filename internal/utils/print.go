package utils

import (
	"fmt"
	"strings"
)

// PrintHeader prints a section header with underline
func PrintHeader(title string) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
}
