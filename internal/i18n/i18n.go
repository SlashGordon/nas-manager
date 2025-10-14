package i18n

import (
	"os"
	"strings"
)

// Translation key constants (enum-like).
const (
	SecurityScanTitle          = "security.scan.title"
	SecurityScanOverall        = "security.scan.overall"
	SecurityScanCritical       = "security.scan.critical"
	SecurityScanCriticalAction = "security.scan.critical.action"
	SecurityScanWarning        = "security.scan.warning"
	SecurityScanWarningAction  = "security.scan.warning.action"
	SecurityScanGood           = "security.scan.good"
	SecurityScanGoodAction     = "security.scan.good.action"
	SecuritySSHTitle           = "security.ssh.title"
	SecurityOptions            = "security.options"
	SecuritySSHWarning         = "security.ssh.warning"
	SecuritySSHCompleted       = "security.ssh.completed"
	SecuritySSHRestart         = "security.ssh.restart"
	SecuritySSHKeys            = "security.ssh.keys"
	SecurityDSMWarning         = "security.dsm.warning"
	SecurityServicesWarning    = "security.services.warning"
	PromptYes                  = "prompt.yes"
	PromptNo                   = "prompt.no"
	PromptTrust                = "prompt.trust"
	// BlocklistUpdating represents the blocklist updating message key.
	BlocklistUpdating            = "blocklist.updating"
	BlocklistProcessing          = "blocklist.processing"
	BlocklistCompleted           = "blocklist.completed"
	BlocklistCleared             = "blocklist.cleared"
	BlocklistAdded               = "blocklist.added"
	BlocklistSafeMode            = "blocklist.safe.mode"
	BlocklistSafeTimer           = "blocklist.safe.timer"
	BlocklistSafeConfirm         = "blocklist.safe.confirm"
	BlocklistSafetyWarning       = "blocklist.safety.warning"
	BlocklistSafetyProceed       = "blocklist.safety.proceed"
	BlocklistSafetySuccess       = "blocklist.safety.success"
	BlocklistSafetyConfirmPrompt = "blocklist.safety.confirm.prompt"
	BlocklistSafetyAutoConfirm   = "blocklist.safety.auto.confirm"
	BlocklistSafetyUserConfirm   = "blocklist.safety.user.confirm"
	BlocklistSafetyTimeout       = "blocklist.safety.timeout"
	// PortscanStarting represents the port scan starting message key.
	PortscanStarting    = "portscan.starting"
	PortscanActive      = "portscan.active"
	PortscanStopped     = "portscan.stopped"
	PortscanSetupError  = "portscan.setup.error"
	PortscanRemoveError = "portscan.remove.error"
	// VulnscanPorts represents the vulnerability scan ports message key.
	VulnscanPorts     = "vulnscan.ports"
	VulnscanServices  = "vulnscan.services"
	VulnscanCompleted = "vulnscan.completed"
	VulnscanOpen      = "vulnscan.open"
	VulnscanRunning   = "vulnscan.running"
	VulnscanWarning   = "vulnscan.warning"
	// DSMHardeningTitle represents the DSM hardening title message key.
	DSMHardeningTitle = "dsm.hardening.title"
	// Certificate messages
	CertificateFound            = "certificate.found"
	CertificateCannotVerify     = "certificate.cannot_verify"
	CertificateMissing          = "certificate.missing"
	CertificateInstallRecommend = "certificate.install.recommend"
	CertificateExpired          = "certificate.expired"
	CertificateRenewRecommend   = "certificate.renew.recommend"
	DSMAutoBlock                = "dsm.autoblock"
	DSMAutoBlockEnabled         = "dsm.autoblock.enabled"
	DSMAutoBlockFailed          = "dsm.autoblock.failed"
	DSMAutoBlockSkipped         = "dsm.autoblock.skipped"
	DSMConfigured               = "dsm.configured"
	DSMRestart                  = "dsm.restart"
	// ServiceHardeningTitle represents the service hardening title message key.
	ServiceHardeningTitle  = "service.hardening.title"
	ServiceDisabling       = "service.disabling"
	ServiceDisabled        = "service.disabled"
	ServiceFailed          = "service.failed"
	ServiceSkipped         = "service.skipped"
	ServiceAlreadyDisabled = "service.already.disabled"
	// ErrorCreatingChain represents the error creating chain message key.
	ErrorCreatingChain = "error.creating.chain"
	ErrorClearingChain = "error.clearing.chain"
	ErrorLinkingChain  = "error.linking.chain"
	ErrorProcessing    = "error.processing"
	TrustingRemaining  = "trusting.remaining"
	// UpdateChecking represents the update checking message key.
	UpdateChecking    = "update.checking"
	UpdateLatest      = "update.latest"
	UpdateAvailable   = "update.available"
	UpdateDownloading = "update.downloading"
	UpdateSuccess     = "update.success"
	UpdateRestart     = "update.restart"
	UpdateFailed      = "update.failed"
	// ACMEIssuing represents the ACME issuing message key.
	ACMEIssuing          = "acme.issuing"
	ACMESuccess          = "acme.success"
	ACMEFailed           = "acme.failed"
	ACMEError            = "acme.error"
	ACMEPermissionDenied = "acme.permission.denied"
	ACMESaved            = "acme.saved"
	ACMECopy             = "acme.copy"
	// DDNSError represents the DDNS error message key.
	DDNSError          = "ddns.error"
	DDNSUpdated        = "ddns.updated"
	DDNSUnchanged      = "ddns.unchanged"
	DDNSUpdateFailed   = "ddns.update.failed"
	DDNSRecordNotFound = "ddns.record.not.found"
	// VersionInfo represents the version info message key.
	VersionInfo = "version.info"
	// CmdSecurityShort represents the command security short description key.
	CmdSecurityShort         = "cmd.security.short"
	CmdSecurityLong          = "cmd.security.long"
	CmdBlocklistShort        = "cmd.blocklist.short"
	CmdBlocklistLong         = "cmd.blocklist.long"
	CmdBlocklistUpdateShort  = "cmd.blocklist.update.short"
	CmdBlocklistUpdateLong   = "cmd.blocklist.update.long"
	CmdBlocklistClearShort   = "cmd.blocklist.clear.short"
	CmdBlocklistClearLong    = "cmd.blocklist.clear.long"
	CmdPortscanShort         = "cmd.portscan.short"
	CmdPortscanLong          = "cmd.portscan.long"
	CmdPortscanStartShort    = "cmd.portscan.start.short"
	CmdPortscanStartLong     = "cmd.portscan.start.long"
	CmdPortscanStopShort     = "cmd.portscan.stop.short"
	CmdPortscanStopLong      = "cmd.portscan.stop.long"
	CmdVulnscanShort         = "cmd.vulnscan.short"
	CmdVulnscanLong          = "cmd.vulnscan.long"
	CmdVulnscanPortsShort    = "cmd.vulnscan.ports.short"
	CmdVulnscanPortsLong     = "cmd.vulnscan.ports.long"
	CmdVulnscanServicesShort = "cmd.vulnscan.services.short"
	CmdVulnscanServicesLong  = "cmd.vulnscan.services.long"
	CmdHardenShort           = "cmd.harden.short"
	CmdHardenLong            = "cmd.harden.long"
	CmdHardenScanShort       = "cmd.harden.scan.short"
	CmdHardenScanLong        = "cmd.harden.scan.long"
	CmdHardenSSHShort        = "cmd.harden.ssh.short"
	CmdHardenSSHLong         = "cmd.harden.ssh.long"
	CmdHardenDSMShort        = "cmd.harden.dsm.short"
	CmdHardenDSMLong         = "cmd.harden.dsm.long"
	CmdHardenServicesShort   = "cmd.harden.services.short"
	CmdHardenServicesLong    = "cmd.harden.services.long"
	CmdHardenShellShort      = "cmd.harden.shell.short"
	CmdHardenShellLong       = "cmd.harden.shell.long"
	CmdUpdateShort           = "cmd.update.short"
	CmdACMEShort             = "cmd.acme.short"
	CmdACMELong              = "cmd.acme.long"
	CmdACMEIssueShort        = "cmd.acme.issue.short"
	CmdDDNSShort             = "cmd.ddns.short"
	CmdDDNSLong              = "cmd.ddns.long"
	CmdDDNSUpdateShort       = "cmd.ddns.update.short"
	CmdVersionShort          = "cmd.version.short"
	// ShellHistoryTitle represents the shell history title message key.
	ShellHistoryTitle      = "shell.history.title"
	ShellHistorySize       = "shell.history.size"
	ShellHistoryCleared    = "shell.history.cleared"
	ShellHistoryConfigured = "shell.history.configured"
	ShellHistorySkipped    = "shell.history.skipped"
	ShellHistoryFailed     = "shell.history.failed"
	// KernelHardeningTitle represents the kernel hardening title message key.
	KernelHardeningTitle      = "kernel.hardening.title"
	KernelHardeningApply      = "kernel.hardening.apply"
	KernelHardeningAdded      = "kernel.hardening.added"
	KernelHardeningFailed     = "kernel.hardening.failed"
	KernelHardeningApplied    = "kernel.hardening.applied"
	KernelHardeningConfigured = "kernel.hardening.configured"
	KernelHardeningSkipped    = "kernel.hardening.skipped"
	// NetworkHardeningTitle represents the network hardening title message key.
	NetworkHardeningTitle      = "network.hardening.title"
	NetworkHardeningApply      = "network.hardening.apply"
	NetworkHardeningAdded      = "network.hardening.added"
	NetworkHardeningFailed     = "network.hardening.failed"
	NetworkHardeningApplied    = "network.hardening.applied"
	NetworkHardeningConfigured = "network.hardening.configured"
	NetworkHardeningSkipped    = "network.hardening.skipped"
	// Common hardening messages
	HardeningNote           = "hardening.note"
	HardeningWarning        = "hardening.warning"
	HardeningShellWarning   = "hardening.shell.warning"
	HardeningKernelWarning  = "hardening.kernel.warning"
	HardeningNetworkWarning = "hardening.network.warning"
	HardeningFailed         = "hardening.failed"
	// Blocklist processing
	BlocklistProcessedIPs = "blocklist.processed.ips"
)

var currentLang = "en"
var translations = map[string]map[string]string{
	"en": {
		SecurityScanTitle:          "Synology NAS Security Hardening Scan",
		SecurityScanOverall:        "OVERALL",
		SecurityScanCritical:       "CRITICAL: Your system has significant security vulnerabilities!",
		SecurityScanCriticalAction: "Immediate action required to secure your NAS.",
		SecurityScanWarning:        "WARNING: Your system needs security improvements.",
		SecurityScanWarningAction:  "Consider addressing the failed checks above.",
		SecurityScanGood:           "GOOD: Your system has strong security posture.",
		SecurityScanGoodAction:     "Continue monitoring and maintaining security settings.",
		SecuritySSHTitle:           "SSH Hardening for Synology NAS",
		SecurityOptions:            "Options: y=apply, n=skip, t=trust (apply all remaining)",
		SecuritySSHWarning:         "WARNING: Test SSH access before applying restrictive settings!",
		SecuritySSHCompleted:       "SSH hardening process completed!",
		SecuritySSHRestart:         "IMPORTANT: Restart SSH service with: synoservice --restart sshd",
		SecuritySSHKeys:            "WARNING: Ensure SSH keys are configured before disabling password auth!",
		SecurityDSMWarning:         "WARNING: Changes require DSM service restart!",
		SecurityServicesWarning:    "WARNING: This will disable system services!",
		PromptYes:                  "y=yes",
		PromptNo:                   "n=no",
		PromptTrust:                "t=trust all",
		// Blocklist
		BlocklistUpdating:            "Updating %d blocklists...",
		BlocklistProcessing:          "Processing %s...",
		BlocklistCompleted:           "Blocklist update completed",
		BlocklistCleared:             "Blocklist cleared",
		BlocklistAdded:               "Added %d rules from %s",
		BlocklistSafeMode:            "🛡️  Safety mode enabled for IP: %s",
		BlocklistSafeTimer:           "⏰ Auto-revert in %v if connection lost",
		BlocklistSafeConfirm:         "✅ Safety mode disabled - changes are permanent",
		BlocklistSafetyWarning:       "Warning: %v",
		BlocklistSafetyProceed:       "Proceeding without safety mode...",
		BlocklistSafetySuccess:       "✅ Blocklist update successful!",
		BlocklistSafetyConfirmPrompt: "Press Ctrl+C to confirm changes and disable safety mode",
		BlocklistSafetyAutoConfirm:   "⏰ Auto-confirmed - changes are now permanent",
		BlocklistSafetyUserConfirm:   "✅ Changes confirmed by user",
		BlocklistSafetyTimeout:       "Or wait for automatic confirmation in 30 seconds...",
		// Port scan
		PortscanStarting:    "Starting port scan detection...",
		PortscanActive:      "Port scan detection active (threshold: %s connections in %s seconds)",
		PortscanStopped:     "Port scan detection stopped",
		PortscanSetupError:  "Error setting up port scan rules: %v",
		PortscanRemoveError: "Error removing port scan rules: %v",
		// Vulnerability scan
		VulnscanPorts:     "Scanning Synology NAS ports on %s...",
		VulnscanServices:  "Scanning running services...",
		VulnscanCompleted: "scan completed",
		VulnscanOpen:      "[OPEN] Port %s - %s",
		VulnscanRunning:   "[RUNNING] %s - %s",
		VulnscanWarning:   "[WARNING] %s",
		// DSM Hardening
		DSMHardeningTitle:   "DSM Security Hardening",
		DSMAutoBlock:        "Enable auto-block for failed logins",
		DSMAutoBlockEnabled: "✓ Enabled auto-block for failed logins",
		DSMAutoBlockFailed:  "✗ Failed to enable auto-block: %v",
		DSMAutoBlockSkipped: "Skipped: auto-block configuration",
		DSMConfigured:       "Already configured: auto-block enabled",
		DSMRestart:          "Restart DSM services to apply changes",
		// Certificate messages
		CertificateFound:            "✓ SSL certificate found",
		CertificateCannotVerify:     "✗ Cannot verify certificate",
		CertificateMissing:          "✗ No SSL certificate found",
		CertificateInstallRecommend: "Install SSL certificate in DSM Control Panel",
		CertificateExpired:          "✗ Certificate is expired or invalid",
		CertificateRenewRecommend:   "Renew the certificate or check the certificate chain",
		// Service Hardening
		ServiceHardeningTitle:  "Service Hardening",
		ServiceDisabling:       "Auto-applying: Disable %s service",
		ServiceDisabled:        "✓ Disabled %s service",
		ServiceFailed:          "✗ Failed to disable %s: %v",
		ServiceSkipped:         "Skipped: %s service",
		ServiceAlreadyDisabled: "Already disabled: %s service",
		// Common
		ErrorCreatingChain: "Error creating chain: %v",
		ErrorClearingChain: "Error clearing chain: %v",
		ErrorLinkingChain:  "Error linking chain: %v",
		ErrorProcessing:    "Error processing %s: %v",
		TrustingRemaining:  "→ Trusting all remaining changes",
		// Update command
		UpdateChecking:    "Checking for updates...",
		UpdateLatest:      "Already running the latest version: %s",
		UpdateAvailable:   "New version available: %s (current: %s)",
		UpdateDownloading: "Downloading %s...",
		UpdateSuccess:     "Successfully updated to version %s",
		UpdateRestart:     "Please restart the application to use the new version.",
		UpdateFailed:      "Update failed: %v",
		// ACME command
		ACMEIssuing:          "Issuing certificate for domain: %s",
		ACMESuccess:          "Certificate for %s issued successfully.",
		ACMEFailed:           "Certificate issue failed: %v",
		ACMEError:            "Error: CF_API_TOKEN, ACME_DOMAIN, and ACME_EMAIL environment variables are required",
		ACMEPermissionDenied: "Permission denied for %s, using fallback directory: %s",
		ACMESaved:            "Certificates saved to fallback directory: %s",
		ACMECopy:             "Please manually copy certificates to: %s",
		// DDNS command
		DDNSError:          "Error: CF_API_TOKEN, CF_ZONE_ID, and CF_RECORD_NAME environment variables are required",
		DDNSUpdated:        "Updated %s %s → %s",
		DDNSUnchanged:      "%s unchanged (%s)",
		DDNSUpdateFailed:   "%s update failed",
		DDNSRecordNotFound: "%s record %s not found",
		// Version command
		VersionInfo: "nas-manager %s\nCommit: %s\nBuilt: %s",
		// Command descriptions
		CmdSecurityShort:         "Security and firewall management",
		CmdSecurityLong:          "Manage IP blocklists, port scanning detection, vulnerability scanning, and system hardening for Synology NAS",
		CmdBlocklistShort:        "Manage IP blocklists",
		CmdBlocklistLong:         "Download and apply IP blocklists from FireHOL to iptables",
		CmdBlocklistUpdateShort:  "Update IP blocklists",
		CmdBlocklistUpdateLong:   "Download latest IP blocklists from FireHOL and update iptables rules (includes safety mode - auto-reverts if connection lost)",
		CmdBlocklistClearShort:   "Clear IP blocklists",
		CmdBlocklistClearLong:    "Remove all blocklist rules from iptables",
		CmdPortscanShort:         "Port scan detection and blocking",
		CmdPortscanLong:          "Monitor and block port scanning attempts",
		CmdPortscanStartShort:    "Start port scan detection",
		CmdPortscanStartLong:     "Start monitoring for port scanning attempts and auto-block offenders",
		CmdPortscanStopShort:     "Stop port scan detection",
		CmdPortscanStopLong:      "Stop port scan monitoring and remove detection rules",
		CmdVulnscanShort:         "Vulnerability scanning",
		CmdVulnscanLong:          "Scan for security vulnerabilities and misconfigurations",
		CmdVulnscanPortsShort:    "Scan open ports",
		CmdVulnscanPortsLong:     "Scan for open ports and identify running services",
		CmdVulnscanServicesShort: "Scan services",
		CmdVulnscanServicesLong:  "Check running services for known vulnerabilities",
		CmdHardenShort:           "System hardening scan",
		CmdHardenLong:            "Scan system settings and propose security improvements",
		CmdHardenScanShort:       "Scan system security",
		CmdHardenScanLong:        "Scan system settings and propose security improvements",
		CmdHardenSSHShort:        "Harden SSH configuration",
		CmdHardenSSHLong:         "Apply security hardening to SSH configuration",
		CmdHardenDSMShort:        "Harden DSM settings",
		CmdHardenDSMLong:         "Apply security hardening to DSM configuration",
		CmdHardenServicesShort:   "Harden system services",
		CmdHardenServicesLong:    "Disable unnecessary system services",
		CmdHardenShellShort:      "Harden shell history",
		CmdHardenShellLong:       "Reduce shell history size and clear sensitive commands",
		CmdUpdateShort:           "Update nas-manager to the latest version",
		CmdACMEShort:             "ACME certificate management",
		CmdACMELong:              "Issue and renew Let's Encrypt certificates via Lego and Cloudflare DNS-01 challenge",
		CmdACMEIssueShort:        "Issue/renew certificate",
		CmdDDNSShort:             "Cloudflare DDNS updater",
		CmdDDNSLong:              "Update Cloudflare DNS records with current public IP",
		CmdDDNSUpdateShort:       "Update DNS records",
		CmdVersionShort:          "Print version information",
		// Shell hardening
		ShellHistoryTitle:      "Shell History Hardening",
		ShellHistorySize:       "Set history size to %d entries",
		ShellHistoryCleared:    "✓ Cleared shell history",
		ShellHistoryConfigured: "✓ Configured history settings",
		ShellHistorySkipped:    "Skipped: shell history hardening",
		ShellHistoryFailed:     "✗ Failed to configure shell history: %v",
		// Kernel hardening
		KernelHardeningTitle:      "Kernel Security Hardening",
		KernelHardeningApply:      "Auto-applying: Kernel security settings",
		KernelHardeningAdded:      "✓ Added: %s",
		KernelHardeningFailed:     "⚠ Failed to apply %s: %v",
		KernelHardeningApplied:    "✓ Kernel security settings applied",
		KernelHardeningConfigured: "Kernel security settings already configured",
		KernelHardeningSkipped:    "Skipped: kernel hardening",
		// Network hardening
		NetworkHardeningTitle:      "Network Security Hardening",
		NetworkHardeningApply:      "Auto-applying: Network security settings",
		NetworkHardeningAdded:      "✓ Added: %s",
		NetworkHardeningFailed:     "⚠ Failed to apply %s: %v",
		NetworkHardeningApplied:    "✓ Network security settings applied",
		NetworkHardeningConfigured: "Network security settings already configured",
		NetworkHardeningSkipped:    "Skipped: network hardening",
		// Common hardening messages
		HardeningNote:           "Note: SSH config changes require 'synoservice --restart sshd' to take effect",
		HardeningWarning:        "Always test SSH access before applying restrictive settings!",
		HardeningShellWarning:   "This will modify shell configuration files!",
		HardeningKernelWarning:  "This will modify kernel security settings!",
		HardeningNetworkWarning: "This will modify network security settings!",
		HardeningFailed:         "%s hardening failed: %v",
		// Blocklist processing
		BlocklistProcessedIPs: "Processed %d unique IPs from %d lists",
	},
	"de": {
		SecurityScanTitle:          "Synology NAS Sicherheitshärtung Scan",
		SecurityScanOverall:        "GESAMT",
		SecurityScanCritical:       "KRITISCH: Ihr System hat erhebliche Sicherheitslücken!",
		SecurityScanCriticalAction: "Sofortiges Handeln erforderlich um Ihr NAS zu sichern.",
		SecurityScanWarning:        "WARNUNG: Ihr System benötigt Sicherheitsverbesserungen.",
		SecurityScanWarningAction:  "Beheben Sie die fehlgeschlagenen Prüfungen oben.",
		SecurityScanGood:           "GUT: Ihr System hat eine starke Sicherheitslage.",
		SecurityScanGoodAction:     "Überwachen und pflegen Sie weiterhin die Sicherheitseinstellungen.",
		SecuritySSHTitle:           "SSH Härtung für Synology NAS",
		SecurityOptions:            "Optionen: y=anwenden, n=überspringen, t=vertrauen (alle übrigen anwenden)",
		SecuritySSHWarning:         "WARNUNG: Testen Sie SSH-Zugang vor restriktiven Einstellungen!",
		SecuritySSHCompleted:       "SSH Härtungsprozess abgeschlossen!",
		SecuritySSHRestart:         "WICHTIG: SSH-Dienst neustarten mit: synoservice --restart sshd",
		SecuritySSHKeys:            "WARNUNG: SSH-Schlüssel konfigurieren vor Deaktivierung der Passwort-Auth!",
		SecurityDSMWarning:         "WARNUNG: Änderungen erfordern DSM-Dienst Neustart!",
		SecurityServicesWarning:    "WARNUNG: Dies wird Systemdienste deaktivieren!",
		PromptYes:                  "y=ja",
		PromptNo:                   "n=nein",
		PromptTrust:                "t=alle vertrauen",
		// Blocklist
		BlocklistUpdating:            "Aktualisiere %d Blocklisten...",
		BlocklistProcessing:          "Verarbeite %s...",
		BlocklistCompleted:           "Blocklist-Aktualisierung abgeschlossen",
		BlocklistCleared:             "Blocklist geleert",
		BlocklistAdded:               "%d Regeln von %s hinzugefügt",
		BlocklistSafeMode:            "🛡️  Sicherheitsmodus aktiviert für IP: %s",
		BlocklistSafeTimer:           "⏰ Auto-Rückgängig in %v bei Verbindungsverlust",
		BlocklistSafeConfirm:         "✅ Sicherheitsmodus deaktiviert - Änderungen sind dauerhaft",
		BlocklistSafetyWarning:       "Warnung: %v",
		BlocklistSafetyProceed:       "Fortfahren ohne Sicherheitsmodus...",
		BlocklistSafetySuccess:       "✅ Blocklist-Update erfolgreich!",
		BlocklistSafetyConfirmPrompt: "Drücken Sie Strg+C um Änderungen zu bestätigen und Sicherheitsmodus zu deaktivieren",
		BlocklistSafetyAutoConfirm:   "⏰ Auto-bestätigt - Änderungen sind jetzt dauerhaft",
		BlocklistSafetyUserConfirm:   "✅ Änderungen vom Benutzer bestätigt",
		BlocklistSafetyTimeout:       "Oder warten Sie 30 Sekunden auf automatische Bestätigung...",
		// Port scan
		PortscanStarting:    "Starte Port-Scan-Erkennung...",
		PortscanActive:      "Port-Scan-Erkennung aktiv (Schwellwert: %s Verbindungen in %s Sekunden)",
		PortscanStopped:     "Port-Scan-Erkennung gestoppt",
		PortscanSetupError:  "Fehler beim Einrichten der Port-Scan-Regeln: %v",
		PortscanRemoveError: "Fehler beim Entfernen der Port-Scan-Regeln: %v",
		// Vulnerability scan
		VulnscanPorts:     "Scanne Synology NAS Ports auf %s...",
		VulnscanServices:  "Scanne laufende Dienste...",
		VulnscanCompleted: "Scan abgeschlossen",
		VulnscanOpen:      "[OFFEN] Port %s - %s",
		VulnscanRunning:   "[LÄUFT] %s - %s",
		VulnscanWarning:   "[WARNUNG] %s",
		// DSM Hardening
		DSMHardeningTitle:   "DSM Sicherheitshärtung",
		DSMAutoBlock:        "Auto-Block für fehlgeschlagene Anmeldungen aktivieren",
		DSMAutoBlockEnabled: "✓ Auto-Block für fehlgeschlagene Anmeldungen aktiviert",
		DSMAutoBlockFailed:  "✗ Auto-Block aktivierung fehlgeschlagen: %v",
		DSMAutoBlockSkipped: "Übersprungen: Auto-Block Konfiguration",
		DSMConfigured:       "Bereits konfiguriert: Auto-Block aktiviert",
		DSMRestart:          "DSM-Dienste neustarten um Änderungen anzuwenden",
		// Certificate messages
		CertificateFound:            "✓ SSL-Zertifikat gefunden",
		CertificateCannotVerify:     "✗ Zertifikat kann nicht überprüft werden",
		CertificateMissing:          "✗ Kein SSL-Zertifikat gefunden",
		CertificateInstallRecommend: "Installieren Sie ein SSL-Zertifikat in der DSM-Systemsteuerung",
		CertificateExpired:          "✗ Zertifikat ist abgelaufen oder ungültig",
		CertificateRenewRecommend:   "Erneuern Sie das Zertifikat oder überprüfen Sie die Zertifikatskette",
		// Service Hardening
		ServiceHardeningTitle:  "Dienst-Härtung",
		ServiceDisabling:       "Auto-Anwendung: %s Dienst deaktivieren",
		ServiceDisabled:        "✓ %s Dienst deaktiviert",
		ServiceFailed:          "✗ %s deaktivierung fehlgeschlagen: %v",
		ServiceSkipped:         "Übersprungen: %s Dienst",
		ServiceAlreadyDisabled: "Bereits deaktiviert: %s Dienst",
		// Common
		ErrorCreatingChain: "Fehler beim Erstellen der Kette: %v",
		ErrorClearingChain: "Fehler beim Leeren der Kette: %v",
		ErrorLinkingChain:  "Fehler beim Verknüpfen der Kette: %v",
		ErrorProcessing:    "Fehler beim Verarbeiten von %s: %v",
		TrustingRemaining:  "→ Vertraue allen verbleibenden Änderungen",
		// Update command
		UpdateChecking:    "Prüfe auf Updates...",
		UpdateLatest:      "Läuft bereits mit der neuesten Version: %s",
		UpdateAvailable:   "Neue Version verfügbar: %s (aktuell: %s)",
		UpdateDownloading: "Lade %s herunter...",
		UpdateSuccess:     "Erfolgreich auf Version %s aktualisiert",
		UpdateRestart:     "Bitte starten Sie die Anwendung neu, um die neue Version zu verwenden.",
		UpdateFailed:      "Update fehlgeschlagen: %v",
		// ACME command
		ACMEIssuing:          "Stelle Zertifikat für Domain aus: %s",
		ACMESuccess:          "Zertifikat für %s erfolgreich ausgestellt.",
		ACMEFailed:           "Zertifikat-Ausstellung fehlgeschlagen: %v",
		ACMEError:            "Fehler: CF_API_TOKEN, ACME_DOMAIN und ACME_EMAIL Umgebungsvariablen sind erforderlich",
		ACMEPermissionDenied: "Berechtigung verweigert für %s, verwende Fallback-Verzeichnis: %s",
		ACMESaved:            "Zertifikate im Fallback-Verzeichnis gespeichert: %s",
		ACMECopy:             "Bitte kopieren Sie Zertifikate manuell nach: %s",
		// DDNS command
		DDNSError:          "Fehler: CF_API_TOKEN, CF_ZONE_ID und CF_RECORD_NAME Umgebungsvariablen sind erforderlich",
		DDNSUpdated:        "%s %s aktualisiert → %s",
		DDNSUnchanged:      "%s unverändert (%s)",
		DDNSUpdateFailed:   "%s Update fehlgeschlagen",
		DDNSRecordNotFound: "%s Eintrag %s nicht gefunden",
		// Version command
		VersionInfo: "nas-manager %s\nCommit: %s\nErstellt: %s",
		// Command descriptions
		CmdSecurityShort:         "Sicherheits- und Firewall-Verwaltung",
		CmdSecurityLong:          "Verwalte IP-Blocklisten, Port-Scan-Erkennung, Schwachstellen-Scans und System-Härtung für Synology NAS",
		CmdBlocklistShort:        "IP-Blocklisten verwalten",
		CmdBlocklistLong:         "Lade IP-Blocklisten von FireHOL herunter und wende sie auf iptables an",
		CmdBlocklistUpdateShort:  "IP-Blocklisten aktualisieren",
		CmdBlocklistUpdateLong:   "Lade neueste IP-Blocklisten von FireHOL herunter und aktualisiere iptables-Regeln (enthält Sicherheitsmodus - macht Rückgängig bei Verbindungsverlust)",
		CmdBlocklistClearShort:   "IP-Blocklisten leeren",
		CmdBlocklistClearLong:    "Entferne alle Blocklist-Regeln aus iptables",
		CmdPortscanShort:         "Port-Scan-Erkennung und -Blockierung",
		CmdPortscanLong:          "Überwache und blockiere Port-Scan-Versuche",
		CmdPortscanStartShort:    "Port-Scan-Erkennung starten",
		CmdPortscanStartLong:     "Starte Überwachung für Port-Scan-Versuche und blockiere Angreifer automatisch",
		CmdPortscanStopShort:     "Port-Scan-Erkennung stoppen",
		CmdPortscanStopLong:      "Stoppe Port-Scan-Überwachung und entferne Erkennungsregeln",
		CmdVulnscanShort:         "Schwachstellen-Scan",
		CmdVulnscanLong:          "Scanne nach Sicherheitslücken und Fehlkonfigurationen",
		CmdVulnscanPortsShort:    "Offene Ports scannen",
		CmdVulnscanPortsLong:     "Scanne nach offenen Ports und identifiziere laufende Dienste",
		CmdVulnscanServicesShort: "Dienste scannen",
		CmdVulnscanServicesLong:  "Prüfe laufende Dienste auf bekannte Schwachstellen",
		CmdHardenShort:           "System-Härtungs-Scan",
		CmdHardenLong:            "Scanne Systemeinstellungen und schlage Sicherheitsverbesserungen vor",
		CmdHardenScanShort:       "System-Sicherheit scannen",
		CmdHardenScanLong:        "Scanne Systemeinstellungen und schlage Sicherheitsverbesserungen vor",
		CmdHardenSSHShort:        "SSH-Konfiguration härten",
		CmdHardenSSHLong:         "Wende Sicherheitshärtung auf SSH-Konfiguration an",
		CmdHardenDSMShort:        "DSM-Einstellungen härten",
		CmdHardenDSMLong:         "Wende Sicherheitshärtung auf DSM-Konfiguration an",
		CmdHardenServicesShort:   "System-Dienste härten",
		CmdHardenServicesLong:    "Deaktiviere unnötige System-Dienste",
		CmdHardenShellShort:      "Shell-Verlauf härten",
		CmdHardenShellLong:       "Reduziere Shell-Verlaufsgröße und lösche sensible Befehle",
		CmdUpdateShort:           "Aktualisiere nas-manager auf die neueste Version",
		CmdACMEShort:             "ACME-Zertifikatsverwaltung",
		CmdACMELong:              "Stelle Let's Encrypt-Zertifikate über Lego und Cloudflare DNS-01-Challenge aus und erneuere sie",
		CmdACMEIssueShort:        "Zertifikat ausstellen/erneuern",
		CmdDDNSShort:             "Cloudflare DDNS-Updater",
		CmdDDNSLong:              "Aktualisiere Cloudflare DNS-Einträge mit aktueller öffentlicher IP",
		CmdDDNSUpdateShort:       "DNS-Einträge aktualisieren",
		CmdVersionShort:          "Versionsinformationen anzeigen",
		// Shell hardening
		ShellHistoryTitle:      "Shell-Verlauf Härtung",
		ShellHistorySize:       "Verlaufsgröße auf %d Einträge setzen",
		ShellHistoryCleared:    "✓ Shell-Verlauf geleert",
		ShellHistoryConfigured: "✓ Verlaufseinstellungen konfiguriert",
		ShellHistorySkipped:    "Übersprungen: Shell-Verlauf Härtung",
		ShellHistoryFailed:     "✗ Shell-Verlauf Konfiguration fehlgeschlagen: %v",
		// Kernel hardening
		KernelHardeningTitle:      "Kernel-Sicherheitshärtung",
		KernelHardeningApply:      "Auto-Anwendung: Kernel-Sicherheitseinstellungen",
		KernelHardeningAdded:      "✓ Hinzugefügt: %s",
		KernelHardeningFailed:     "⚠ Anwendung fehlgeschlagen %s: %v",
		KernelHardeningApplied:    "✓ Kernel-Sicherheitseinstellungen angewendet",
		KernelHardeningConfigured: "Kernel-Sicherheitseinstellungen bereits konfiguriert",
		KernelHardeningSkipped:    "Übersprungen: Kernel-Härtung",
		// Network hardening
		NetworkHardeningTitle:      "Netzwerk-Sicherheitshärtung",
		NetworkHardeningApply:      "Auto-Anwendung: Netzwerk-Sicherheitseinstellungen",
		NetworkHardeningAdded:      "✓ Hinzugefügt: %s",
		NetworkHardeningFailed:     "⚠ Anwendung fehlgeschlagen %s: %v",
		NetworkHardeningApplied:    "✓ Netzwerk-Sicherheitseinstellungen angewendet",
		NetworkHardeningConfigured: "Netzwerk-Sicherheitseinstellungen bereits konfiguriert",
		NetworkHardeningSkipped:    "Übersprungen: Netzwerk-Härtung",
		// Common hardening messages
		HardeningNote:           "Hinweis: SSH-Konfigurationsänderungen erfordern 'synoservice --restart sshd'",
		HardeningWarning:        "Testen Sie immer SSH-Zugang vor restriktiven Einstellungen!",
		HardeningShellWarning:   "Dies wird Shell-Konfigurationsdateien ändern!",
		HardeningKernelWarning:  "Dies wird Kernel-Sicherheitseinstellungen ändern!",
		HardeningNetworkWarning: "Dies wird Netzwerk-Sicherheitseinstellungen ändern!",
		HardeningFailed:         "%s Härtung fehlgeschlagen: %v",
		// Blocklist processing
		BlocklistProcessedIPs: "%d eindeutige IPs aus %d Listen verarbeitet",
	},
}

func init() {
	if lang := os.Getenv("LANG"); lang != "" {
		if code := strings.Split(lang, "_")[0]; code != "" {
			SetLanguage(code)
		}
	}
}

func SetLanguage(lang string) {
	if _, exists := translations[lang]; exists {
		currentLang = lang
	} else {
		currentLang = "en"
	}
}

func T(key string) string {
	if trans, exists := translations[currentLang][key]; exists {
		return trans
	}
	if trans, exists := translations["en"][key]; exists {
		return trans
	}
	return key
}
