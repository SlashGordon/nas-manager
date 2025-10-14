package constants

// FilePermission0600 represents file permission 0600
const FilePermission0600 = 0600

// FilePermission0644 represents file permission 0644
const FilePermission0644 = 0644

// FilePermission0755 represents file permission 0755
const FilePermission0755 = 0755

// SplitParts represents the number of parts for splitting operations
const SplitParts = 2

// PtraceScope represents the ptrace scope value
const PtraceScope = 2

// HistorySize represents the shell history size
const HistorySize = 100

// MaxConnections represents the maximum connections threshold
const MaxConnections = 10

// Percentage100 represents 100 percent
const Percentage100 = 100

// Percentage90 represents 90 percent
const Percentage90 = 90

// Percentage80 represents 80 percent
const Percentage80 = 80

// Percentage70 represents 70 percent
const Percentage70 = 70

// Percentage60 represents 60 percent
const Percentage60 = 60

// TimeoutSeconds represents timeout in seconds
const TimeoutSeconds = 30

// TimeoutSecs represents timeout in seconds (alias)
const TimeoutSecs = 30

// MaxAdmins represents the maximum number of administrators
const MaxAdmins = 3

// AdminOffset represents the admin offset
const AdminOffset = 1

// ChoiceYes represents the yes choice
const ChoiceYes = "yes"

// ChoiceNo represents the no choice
const ChoiceNo = "no"

// ChoiceTrust represents the trust choice
const ChoiceTrust = "trust"

// SynoCertificatePath is the default path to the Synology system certificate
const SynoCertificatePath = "/usr/syno/etc/certificate/system/default/cert.pem"

// SynoCertDir is the directory containing Synology system certificates
const SynoCertDir = "/usr/syno/etc/certificate/system/default"

// SynoServiceCtlPath is the path to Synology's service control binary
const SynoServiceCtlPath = "/usr/syno/sbin/synoservicectl"

// SynoSecurityScanConf is the security scan configuration file
const SynoSecurityScanConf = "/usr/syno/etc/security_scan/security_scan.conf"

// SynoSMBConf is the Samba configuration file
const SynoSMBConf = "/usr/syno/etc/smb.conf"

// SynoPwPolicyConf is the Synology password policy configuration file
const SynoPwPolicyConf = "/usr/syno/etc/pwpolicy.conf"

// SynoVolume1Path points to the first volume used for find operations
const SynoVolume1Path = "/volume1"

// SynoAdminHome is the home path for the default admin user
const SynoAdminHome = "/var/services/homes/admin"

// CloudflareIPsV4URL published IP list URLs
const CloudflareIPsV4URL = "https://www.cloudflare.com/ips-v4"

// CloudflareIPsV6URL published IP list URLs
const CloudflareIPsV6URL = "https://www.cloudflare.com/ips-v6"
