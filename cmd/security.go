package cmd

import (
	"github.com/SlashGordon/nas-manager/cmd/security"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: i18n.T(i18n.CmdSecurityShort),
	Long:  i18n.T(i18n.CmdSecurityLong),
}

func init() {
	securityCmd.AddCommand(security.BlocklistCmd)
	securityCmd.AddCommand(security.PortscanCmd)
	securityCmd.AddCommand(security.VulnscanCmd)
	securityCmd.AddCommand(security.HardenCmd)
	securityCmd.AddCommand(security.CloudflareCmd)
}
