package harden

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
)

// PromptUser prompts the user for confirmation
func PromptUser(message string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		if _, err := fmt.Fprintf(os.Stdout, "%s [%s, %s, %s]: ", message, i18n.T(i18n.PromptYes), i18n.T(i18n.PromptNo), i18n.T(i18n.PromptTrust)); err != nil {
			return "no"
		}

		input, _ := reader.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(input))

		switch choice {
		case "y", constants.ChoiceYes:
			return constants.ChoiceYes
		case "n", "no":
			return "no"
		case "t", constants.ChoiceTrust:
			return constants.ChoiceTrust
		default:
			if _, err := fmt.Fprintf(os.Stdout, "Please enter %s, %s, or %s\n", i18n.T(i18n.PromptYes), i18n.T(i18n.PromptNo), i18n.T(i18n.PromptTrust)); err != nil {
				return "no"
			}
		}
	}
}
