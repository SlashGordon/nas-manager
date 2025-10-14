package harden

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/SlashGordon/nas-manager/internal/constants"
)

func CheckSharedFolders() []HardeningResult {
	results := []HardeningResult{}

	if content, err := os.ReadFile(constants.SynoSMBConf); err == nil {
		config := string(content)
		if strings.Contains(config, "guest ok = yes") {
			results = append(results, HardeningResult{
				false,
				"Guest access enabled on shared folders",
				"Disable guest access in Control Panel > Shared Folder",
			})
		} else {
			results = append(results, HardeningResult{true, "No guest access on shared folders", ""})
		}
	} else {
		results = append(results, HardeningResult{false, "Cannot check shared folder settings", "Manually verify shared folder permissions"})
	}
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "find", constants.SynoVolume1Path, "-type", "d", "-perm", "777", "-ls")
	if output, err := cmd.Output(); err == nil {
		if len(strings.TrimSpace(string(output))) > 0 {
			results = append(results, HardeningResult{
				false,
				"World-writable folders found",
				"Review and restrict folder permissions",
			})
		} else {
			results = append(results, HardeningResult{true, "No world-writable folders found", ""})
		}
	} else {
		results = append(results, HardeningResult{false, "Cannot check folder permissions", "Manually verify folder permissions"})
	}

	return results
}
