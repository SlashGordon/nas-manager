package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/SlashGordon/nas-manager/internal/constants"
)

func CheckSynologyUsers() []HardeningResult {
	results := []HardeningResult{}
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "synogroup", "--get", "administrators")
	if output, err := cmd.Output(); err == nil {
		admins := strings.Fields(string(output))
		if len(admins) > constants.MaxAdmins {
			results = append(results, HardeningResult{
				false,
				fmt.Sprintf("%d admin users found", len(admins)-constants.AdminOffset),
				"Review admin user accounts and remove unnecessary ones",
			})
		} else {
			results = append(results, HardeningResult{true, "Admin user count is reasonable", ""})
		}
	} else {
		results = append(results, HardeningResult{false, "Cannot check admin users", "Manually verify admin user accounts"})
	}

	if content, err := os.ReadFile(constants.SynoPwPolicyConf); err == nil {
		config := string(content)
		if strings.Contains(config, "min_len=8") {
			results = append(results, HardeningResult{true, "Password minimum length policy set", ""})
		} else {
			results = append(results, HardeningResult{false, "Weak password policy", "Set stronger password requirements in DSM User settings"})
		}
	} else {
		results = append(results, HardeningResult{false, "Cannot check password policy", "Manually verify password policy settings"})
	}

	return results
}
