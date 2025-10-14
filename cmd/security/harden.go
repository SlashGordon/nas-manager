package security

import (
	"strings"

	"github.com/SlashGordon/nas-manager/cmd/security/harden"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/spf13/cobra"
)

var HardenCmd = &cobra.Command{
	Use:   "harden",
	Short: i18n.T(i18n.CmdHardenShort),
	Long:  i18n.T(i18n.CmdHardenLong),
}

var scanHardenCmd = &cobra.Command{
	Use:   "scan",
	Short: i18n.T(i18n.CmdHardenScanShort),
	Long:  i18n.T(i18n.CmdHardenScanLong),
	Run:   runHardenScan,
}

var sshHardenCmd = &cobra.Command{
	Use:   "ssh",
	Short: i18n.T(i18n.CmdHardenSSHShort),
	Long:  i18n.T(i18n.CmdHardenSSHLong),
	Run:   runSSHHarden,
}

var dsmHardenCmd = &cobra.Command{
	Use:   "dsm",
	Short: i18n.T(i18n.CmdHardenDSMShort),
	Long:  i18n.T(i18n.CmdHardenDSMLong),
	Run:   runDSMHarden,
}

var serviceHardenCmd = &cobra.Command{
	Use:   "services",
	Short: i18n.T(i18n.CmdHardenServicesShort),
	Long:  i18n.T(i18n.CmdHardenServicesLong),
	Run:   runServiceHarden,
}

var shellHardenCmd = &cobra.Command{
	Use:   "shell",
	Short: i18n.T(i18n.CmdHardenShellShort),
	Long:  i18n.T(i18n.CmdHardenShellLong),
	Run:   runShellHarden,
}

var kernelHardenCmd = &cobra.Command{
	Use:   "kernel",
	Short: "Harden kernel security",
	Long:  "Apply kernel security settings (ptrace, ASLR, core dumps)",
	Run:   runKernelHarden,
}

var networkHardenCmd = &cobra.Command{
	Use:   "network",
	Short: "Harden network security",
	Long:  "Apply network security settings (IP forwarding, redirects, SYN cookies)",
	Run:   runNetworkHarden,
}

func runHardenScan(_ *cobra.Command, _ []string) {
	title := i18n.T(i18n.SecurityScanTitle)
	log.Info(title)
	log.Info(strings.Repeat("=", len(title)))

	checks := []harden.HardeningCheck{
		{Name: "DSM Security Settings", Fn: harden.CheckDSMSecurity},
		{Name: "SSH Configuration", Fn: harden.CheckSSHHardening},
		{Name: "Shared Folders", Fn: harden.CheckSharedFolders},
		{Name: "User Accounts", Fn: harden.CheckSynologyUsers},
		{Name: "Network Services", Fn: harden.CheckSynologyServices},
		{Name: "Certificate Status", Fn: harden.CheckCertificates},
		{Name: "Shell History", Fn: harden.CheckShellHistory},
	}

	allResults := []harden.HardeningResult{}

	for _, check := range checks {
		log.Infof("\n[%s]", check.Name)
		results := check.Fn()
		allResults = append(allResults, results...)

		categoryScore := harden.CalculateScore(results)

		for _, result := range results {
			if result.Secure {
				log.Infof("  ✓ %s", result.Message)
			} else {
				log.Warnf("  ✗ %s", result.Message)
				if result.Recommendation != "" {
					log.Infof("    → %s", result.Recommendation)
				}
			}
		}
		log.Infof("  Score: %s", categoryScore.String())
	}

	overallScore := harden.CalculateScore(allResults)
	const separatorLength = 50
	log.Info(strings.Repeat("=", separatorLength))
	log.Infof("%s %s", i18n.T(i18n.SecurityScanOverall), overallScore.String())
	log.Info(strings.Repeat("=", separatorLength))

	const criticalThreshold = 70
	const warningThreshold = 85
	switch {
	case overallScore.Percentage < criticalThreshold:
		log.Errorf("⚠️  %s", i18n.T(i18n.SecurityScanCritical))
		log.Info(i18n.T(i18n.SecurityScanCriticalAction))
	case overallScore.Percentage < warningThreshold:
		log.Warnf("⚠️  %s", i18n.T(i18n.SecurityScanWarning))
		log.Info(i18n.T(i18n.SecurityScanWarningAction))
	default:
		log.Infof("✓ %s", i18n.T(i18n.SecurityScanGood))
		log.Info(i18n.T(i18n.SecurityScanGoodAction))
	}

	log.Info(i18n.T(i18n.HardeningNote))
	log.Warn(i18n.T(i18n.HardeningWarning))
}

func runSSHHarden(_ *cobra.Command, _ []string) {
	title := i18n.T(i18n.SecuritySSHTitle)
	log.Info(title)
	log.Info(strings.Repeat("=", len(title)))
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.SecuritySSHWarning))

	if err := harden.ApplySSHHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "SSH", err)
		return
	}

	log.Info(i18n.T(i18n.SecuritySSHCompleted))
	log.Info(i18n.T(i18n.SecuritySSHRestart))
	log.Info(i18n.T(i18n.SecuritySSHKeys))
}

func runDSMHarden(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.SecurityDSMWarning))

	if err := harden.ApplyDSMHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "DSM", err)
	}
}

func runServiceHarden(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.SecurityServicesWarning))

	if err := harden.ApplyServiceHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "Service", err)
	}
}

func runShellHarden(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.HardeningShellWarning))

	if err := harden.ApplyShellHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "Shell", err)
	}
}

func runKernelHarden(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.HardeningKernelWarning))

	if err := harden.ApplyKernelHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "Kernel", err)
	}
}

func runNetworkHarden(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.SecurityOptions))
	log.Warn(i18n.T(i18n.HardeningNetworkWarning))

	if err := harden.ApplyNetworkHardening(); err != nil {
		log.Errorf(i18n.T(i18n.HardeningFailed), "Network", err)
	}
}

func init() {
	HardenCmd.AddCommand(scanHardenCmd)
	HardenCmd.AddCommand(sshHardenCmd)
	HardenCmd.AddCommand(dsmHardenCmd)
	HardenCmd.AddCommand(serviceHardenCmd)
	HardenCmd.AddCommand(shellHardenCmd)
	HardenCmd.AddCommand(kernelHardenCmd)
	HardenCmd.AddCommand(networkHardenCmd)
}
