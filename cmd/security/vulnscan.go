package security

import (
	"context"
	"fmt"

	"os/exec"
	"strings"

	"github.com/SlashGordon/nas-manager/internal"
	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/spf13/cobra"
)

var VulnscanCmd = &cobra.Command{
	Use:   "vulnscan",
	Short: i18n.T(i18n.CmdVulnscanShort),
	Long:  i18n.T(i18n.CmdVulnscanLong),
}

var scanPortsCmd = &cobra.Command{
	Use:   "ports",
	Short: i18n.T(i18n.CmdVulnscanPortsShort),
	Long:  i18n.T(i18n.CmdVulnscanPortsLong),
	Run:   runScanPorts,
}

var scanServicesCmd = &cobra.Command{
	Use:   "services",
	Short: i18n.T(i18n.CmdVulnscanServicesShort),
	Long:  i18n.T(i18n.CmdVulnscanServicesLong),
	Run:   runScanServices,
}

func runScanPorts(_ *cobra.Command, _ []string) {
	target := internal.GetEnv("VULNSCAN_TARGET", "localhost")
	ports := internal.GetEnv("VULNSCAN_PORTS", "22,80,443,5000,5001,873,548,139,445,2049")

	log.Infof(i18n.T(i18n.VulnscanPorts), target)

	for _, port := range strings.Split(ports, ",") {
		port = strings.TrimSpace(port)
		if scanPort(target, port) {
			service := identifyService(port)
			log.Infof(i18n.T(i18n.VulnscanOpen), port, service)
		}
	}

	log.Infof("Port %s", i18n.T(i18n.VulnscanCompleted))
}

func runScanServices(_ *cobra.Command, _ []string) {
	log.Info(i18n.T(i18n.VulnscanServices))

	vulnServices := []string{"ssh", "apache2", "nginx", "mysql", "postgresql"}

	for _, service := range vulnServices {
		if checkService(service) {
			version := getServiceVersion(service)
			log.Infof(i18n.T(i18n.VulnscanRunning), service, version)
			checkVulnerabilities(service, version)
		}
	}

	log.Infof("Service %s", i18n.T(i18n.VulnscanCompleted))
}

func scanPort(host, port string) bool {
	cmd := exec.Command("nc", "-z", "-w", fmt.Sprintf("%d", constants.TimeoutSecs), host, port)
	return cmd.Run() == nil
}

func identifyService(port string) string {
	services := map[string]string{
		"22":   "SSH",
		"80":   "HTTP (DSM)",
		"443":  "HTTPS (DSM)",
		"5000": "DSM HTTP",
		"5001": "DSM HTTPS",
		"873":  "rsync",
		"548":  "AFP (Apple Filing)",
		"139":  "NetBIOS",
		"445":  "SMB/CIFS",
		"2049": "NFS",
		"21":   "FTP",
		"25":   "SMTP",
		"110":  "POP3",
		"143":  "IMAP",
		"993":  "IMAPS",
		"995":  "POP3S",
	}

	if service, exists := services[port]; exists {
		return service
	}
	const unknownService = "Unknown"
	return unknownService
}

func checkService(service string) bool {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", service)
	return cmd.Run() == nil
}

func getServiceVersion(service string) string {
	const unknownVersion = "Unknown"
	var cmd *exec.Cmd
	ctx := context.Background()

	switch service {
	case "ssh":
		cmd = exec.CommandContext(ctx, "ssh", "-V")
	case "apache2":
		cmd = exec.CommandContext(ctx, "apache2", "-v")
	case "nginx":
		cmd = exec.CommandContext(ctx, "nginx", "-v")
	case "mysql":
		cmd = exec.CommandContext(ctx, "mysql", "--version")
	case "postgresql":
		cmd = exec.CommandContext(ctx, "psql", "--version")
	default:
		return unknownVersion
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return unknownVersion
	}

	return strings.TrimSpace(string(output))
}

func checkVulnerabilities(service, _ string) {
	vulns := getKnownVulnerabilities(service)

	for _, vuln := range vulns {
		log.Warnf("  "+i18n.T(i18n.VulnscanWarning), vuln)
	}
}

func getKnownVulnerabilities(service string) []string {
	vulns := make([]string, 0)

	switch service {
	case "ssh":
		vulns = append(vulns, "Check for weak SSH configurations")
		vulns = append(vulns, "Ensure key-based authentication is enabled")
	case "apache2", "nginx":
		vulns = append(vulns, "Check for outdated web server version")
		vulns = append(vulns, "Verify SSL/TLS configuration")
	case "mysql", "postgresql":
		vulns = append(vulns, "Check for default credentials")
		vulns = append(vulns, "Verify database access controls")
	}

	return vulns
}

func init() {
	VulnscanCmd.AddCommand(scanPortsCmd)
	VulnscanCmd.AddCommand(scanServicesCmd)
}
