package security

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal"
	"github.com/SlashGordon/nas-manager/internal/blocklist"
	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/http"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/SlashGordon/nas-manager/internal/logger"
	"github.com/spf13/cobra"
)

var cloudflareNetsCache []*net.IPNet

// getCloudflareNets downloads Cloudflare's published IP ranges and returns parsed IPNet entries.
// The result is cached for subsequent calls.
func getCloudflareNets() ([]*net.IPNet, error) {
	if len(cloudflareNetsCache) > 0 {
		return cloudflareNetsCache, nil
	}

	urls := []string{
		constants.CloudflareIPsV4URL,
		constants.CloudflareIPsV6URL,
	}

	var nets []*net.IPNet
	ctx := context.Background()
	for _, u := range urls {
		scanner, closer, err := http.GetScanner(ctx, u)
		if err != nil {
			// try next URL or return error if none succeed
			return nil, err
		}
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, n, err := net.ParseCIDR(line); err == nil {
				nets = append(nets, n)
			}
		}
		closer()
	}

	cloudflareNetsCache = nets
	return cloudflareNetsCache, nil
}

var BlocklistCmd = &cobra.Command{
	Use:   "blocklist",
	Short: i18n.T(i18n.CmdBlocklistShort),
	Long:  i18n.T(i18n.CmdBlocklistLong),
}

var updateBlocklistCmd = &cobra.Command{
	Use:   "update",
	Short: i18n.T(i18n.CmdBlocklistUpdateShort),
	Long:  i18n.T(i18n.CmdBlocklistUpdateLong),
	Run: func(cmd *cobra.Command, args []string) {
		runUpdateBlocklist(cmd, args)
	},
}

var clearBlocklistCmd = &cobra.Command{
	Use:   "clear",
	Short: i18n.T(i18n.CmdBlocklistClearShort),
	Long:  i18n.T(i18n.CmdBlocklistClearLong),
	Run: func(cmd *cobra.Command, args []string) {
		runClearBlocklist(cmd, args)
	},
}

// Global logger instance for security package
var log *logger.Logger

// SetLogger sets the logger instance for the security package
func SetLogger(l *logger.Logger) {
	log = l
}

type Blocklist struct {
	Name string
	URL  string
}

func runUpdateBlocklist(cmd *cobra.Command, _ []string) {
	// read flags from provided cmd
	filterCloudflare := true
	filterLocal := true
	if f, err := cmd.Flags().GetBool("filter-cloudflare"); err == nil {
		filterCloudflare = f
	}
	if f, err := cmd.Flags().GetBool("filter-local"); err == nil {
		filterLocal = f
	}

	ctx := context.Background()
	lists := GetBlocklists()
	chain := internal.GetEnv("SECURITY_CHAIN", "BLOCKLIST")
	const revertDelayMinutes = 5
	revertDelay := revertDelayMinutes * time.Minute

	// Initialize safety manager
	safety := NewSafetyManager(chain, revertDelay)
	if err := safety.Start(); err != nil {
		log.Warnf(i18n.T(i18n.BlocklistSafetyWarning), err)
		log.Info(i18n.T(i18n.BlocklistSafetyProceed))
	}

	log.Infof(i18n.T(i18n.BlocklistUpdating), len(lists))

	if err := CreateChain(ctx, chain); err != nil {
		log.Errorf(i18n.T(i18n.ErrorCreatingChain), err)
		return
	}

	if err := ClearChain(ctx, chain); err != nil {
		log.Errorf(i18n.T(i18n.ErrorClearingChain), err)
		return
	}

	// Extract and merge all IPs from all lists (apply optional filters)
	allIPs, err := ExtractAndMergeIPs(lists, filterCloudflare, filterLocal)
	if err != nil {
		log.Errorf("Error extracting IPs: %v", err)
		return
	}

	log.Infof(i18n.T(i18n.BlocklistProcessedIPs), len(allIPs), len(lists))

	// Add all unique IPs to iptables
	for _, ip := range allIPs {
		if err := AddDropRule(ctx, chain, ip); err != nil {
			continue
		}
		// Refresh safety timer periodically
		if safety != nil {
			safety.Refresh()
		}
	}

	if err := LinkChain(ctx, chain); err != nil {
		log.Errorf(i18n.T(i18n.ErrorLinkingChain), err)
		return
	}

	log.Info(i18n.T(i18n.BlocklistCompleted))

	if safety != nil {
		log.Infof("\n%s", i18n.T(i18n.BlocklistSafetySuccess))
		log.Info(i18n.T(i18n.BlocklistSafetyConfirmPrompt))
		log.Info(i18n.T(i18n.BlocklistSafetyTimeout))

		// Wait for user confirmation or timeout
		const confirmTimeoutSeconds = 30
		confirmTimer := time.NewTimer(confirmTimeoutSeconds * time.Second)
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		select {
		case <-confirmTimer.C:
			log.Infof("\n%s", i18n.T(i18n.BlocklistSafetyAutoConfirm))
			safety.Stop()
		case <-interrupt:
			log.Infof("\n%s", i18n.T(i18n.BlocklistSafetyUserConfirm))
			safety.Stop()
		}
	}
}

func runClearBlocklist(_ *cobra.Command, _ []string) {
	ctx := context.Background()
	chain := internal.GetEnv("SECURITY_CHAIN", "BLOCKLIST")

	if err := ClearChain(ctx, chain); err != nil {
		log.Errorf(i18n.T(i18n.ErrorClearingChain), err)
		return
	}

	log.Info(i18n.T(i18n.BlocklistCleared))
}

func GetBlocklists() []Blocklist {
	// Comprehensive blocklist sources organized by category
	defaultLists := map[string]string{
		// Safe & General
		"firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		"firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
		"spamhaus_drop":  "https://www.spamhaus.org/drop/drop.lasso",
		"spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.lasso",
		"dshield":        "https://iplists.firehol.org/files/dshield.netset",
		// Malware & Botnets
		"feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		"sslbl_botnet":  "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
		"threatfox":     "https://threatfox.abuse.ch/downloads/ipblocklist.txt",
		// Brute Force / Abuse
		"ci_army":      "https://cinsscore.com/list/ci-badguys.txt",
		"blocklist_de": "https://lists.blocklist.de/lists/all.txt",
		// Privacy / TOR
		"tor_exits": "https://check.torproject.org/exit-addresses",
		// Aggregated Lists
		"ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
	}

	var lists []Blocklist

	// Check for custom lists first
	if custom := internal.GetEnv("SECURITY_CUSTOM_LISTS", ""); custom != "" {
		// Custom lists provided - only use these (supports local files)
		for _, item := range strings.Split(custom, ",") {
			parts := strings.Split(strings.TrimSpace(item), "=")
			if len(parts) == constants.SplitParts {
				lists = append(lists, Blocklist{parts[0], parts[1]})
			}
		}
	} else {
		// No custom lists - use selected defaults (safe starter set)
		selected := internal.GetEnv("SECURITY_DEFAULT_LISTS", "firehol_level1,spamhaus_drop,dshield")
		for _, name := range strings.Split(selected, ",") {
			name = strings.TrimSpace(name)
			if url, exists := defaultLists[name]; exists {
				lists = append(lists, Blocklist{name, url})
			}
		}
	}

	return lists
}

// ExtractAndMergeIPs extracts IPs from provided blocklists and applies optional filters.
func ExtractAndMergeIPs(lists []Blocklist, filterCloudflare bool, filterLocal bool) ([]string, error) {
	ipSet := make(map[string]bool)

	var cloudflareNets []*net.IPNet
	if filterCloudflare {
		// use live Cloudflare lists only; if fetching fails, no Cloudflare filtering will be applied
		if nets, err := getCloudflareNets(); err == nil {
			cloudflareNets = nets
		}
	}

	isLocal := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		// Check IPv4 private ranges and loopback
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		if ip4 := ip.To4(); ip4 != nil {
			// 10.0.0.0/8
			if ip4[0] == 10 {
				return true
			}
			// 172.16.0.0/12
			if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
				return true
			}
			// 192.168.0.0/16
			if ip4[0] == 192 && ip4[1] == 168 {
				return true
			}
			// 169.254.0.0/16 link-local
			if ip4[0] == 169 && ip4[1] == 254 {
				return true
			}
			return false
		}
		// IPv6 unique local addresses fc00::/7
		if ip.To16() != nil {
			if ip[0]&0xfe == 0xfc {
				return true
			}
		}
		return false
	}

	for _, list := range lists {
		log.Infof(i18n.T(i18n.BlocklistProcessing), list.Name)

		var scanner *bufio.Scanner
		var closer func()

		// Support local files and URLs
		if strings.HasPrefix(list.URL, "http://") || strings.HasPrefix(list.URL, "https://") {
			var err error
			scanner, closer, err = http.GetScanner(context.Background(), list.URL)
			if err != nil {
				log.Errorf(i18n.T(i18n.ErrorProcessing), list.Name, err)
				continue
			}
		} else {
			// Local file
			file, err := fs.Open(list.URL)
			if err != nil {
				log.Errorf(i18n.T(i18n.ErrorProcessing), list.Name, err)
				continue
			}
			scanner = bufio.NewScanner(file)
			closer = func() { file.Close() }
		}

		count := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Parse line using regex patterns
			cleaned := blocklist.ParseLine(line, list.Name)
			if cleaned == "" || !blocklist.ValidateIP(cleaned) {
				continue
			}

			// Filter Cloudflare ranges
			if filterCloudflare {
				parsedIP := net.ParseIP(strings.Split(cleaned, "/")[0])
				if parsedIP != nil {
					skip := false
					for _, n := range cloudflareNets {
						if n.Contains(parsedIP) {
							skip = true
							break
						}
					}
					if skip {
						continue
					}
				}
			}

			// Filter local/private addresses
			if filterLocal {
				parsedIP := net.ParseIP(strings.Split(cleaned, "/")[0])
				if isLocal(parsedIP) {
					continue
				}
			}

			// Add to set (automatically deduplicates)
			if !ipSet[cleaned] {
				ipSet[cleaned] = true
				count++
			}
		}

		closer()
		log.Infof(i18n.T(i18n.BlocklistAdded), count, list.Name)
	}

	// Convert set to slice
	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}

	return uniqueIPs, nil
}

func init() {
	BlocklistCmd.AddCommand(updateBlocklistCmd)
	BlocklistCmd.AddCommand(clearBlocklistCmd)
}
