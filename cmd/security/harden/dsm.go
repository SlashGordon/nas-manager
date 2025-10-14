package harden

import (
	"os"
	"strings"

	"github.com/SlashGordon/nas-manager/internal/constants"
)

func CheckDSMSecurity() []HardeningResult {
	results := []HardeningResult{}

	if content, err := os.ReadFile(constants.SynoSecurityScanConf); err == nil {
		config := string(content)
		if strings.Contains(config, "enable_auto_block=true") {
			results = append(results, HardeningResult{true, "Auto-block enabled for failed logins", ""})
		} else {
			results = append(results, HardeningResult{false, "Auto-block not configured", "Enable auto-block in DSM Security settings"})
		}
	} else {
		results = append(results, HardeningResult{false, "Cannot check DSM security settings", "Verify DSM security configuration manually"})
	}

	if _, err := os.Stat("/var/services/homes/admin"); err == nil {
		results = append(results, HardeningResult{
			false,
			"Default admin account exists",
			"Disable or rename default admin account in DSM",
		})
	} else {
		results = append(results, HardeningResult{true, "Default admin account disabled", ""})
	}

	return results
}
