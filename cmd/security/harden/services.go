package harden

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func CheckSynologyServices() []HardeningResult {
	results := []HardeningResult{}

	services := map[string]string{
		"ftpd":    "FTP Server",
		"telnetd": "Telnet",
		"rsyncd":  "rsync",
		"snmpd":   "SNMP",
		"upnpd":   "UPnP",
	}

	for service, name := range services {
		ctx := context.Background()
		cmd := exec.CommandContext(ctx, "synoservice", "--status", service)
		if output, err := cmd.Output(); err == nil {
			if strings.Contains(string(output), "start") {
				results = append(results, HardeningResult{
					false,
					fmt.Sprintf("%s service is running", name),
					fmt.Sprintf("Disable %s if not needed in DSM Control Panel", name),
				})
			} else {
				results = append(results, HardeningResult{true, fmt.Sprintf("%s service is disabled", name), ""})
			}
		}
	}

	return results
}
