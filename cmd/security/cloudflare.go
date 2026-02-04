package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/SlashGordon/nas-manager/internal/utils"
	"github.com/spf13/cobra"
)

// CloudflareRule represents a Cloudflare WAF rule
type CloudflareRule struct {
	ID          string              `json:"id,omitempty"`
	Action      string              `json:"action"`
	Description string              `json:"description"`
	Enabled     bool                `json:"enabled"`
	Expression  string              `json:"expression"`
	Ref         string              `json:"ref,omitempty"`
	LastUpdated string              `json:"last_updated,omitempty"`
	Version     string              `json:"version,omitempty"`
	Position    *CloudflarePosition `json:"position,omitempty"`
}

// CloudflarePosition represents rule position in ruleset
type CloudflarePosition struct {
	Index  int    `json:"index,omitempty"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// CloudflareRuleset represents a Cloudflare ruleset
type CloudflareRuleset struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Kind        string           `json:"kind"`
	Phase       string           `json:"phase"`
	Rules       []CloudflareRule `json:"rules"`
}

// CloudflareResponse represents Cloudflare API response
type CloudflareResponse struct {
	Success  bool              `json:"success"`
	Errors   []CloudflareError `json:"errors"`
	Messages []string          `json:"messages"`
	Result   json.RawMessage   `json:"result"`
}

// CloudflareError represents Cloudflare API error
type CloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CloudflareClient handles Cloudflare API interactions
type CloudflareClient struct {
	apiToken string
	baseURL  string
	client   *http.Client
}

// NewCloudflareClient creates a new Cloudflare API client
func NewCloudflareClient(apiToken string) *CloudflareClient {
	return &CloudflareClient{
		apiToken: apiToken,
		baseURL:  "https://api.cloudflare.com/client/v4",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getIPv6NetworkIdentifier extracts the network identifier (first 64 bits) from an IPv6 address
func getIPv6NetworkIdentifier(ipv6 string) string {
	if ipv6 == "" {
		return ""
	}
	// Split the IPv6 address into parts
	parts := strings.Split(ipv6, ":")
	if len(parts) < 4 {
		return ""
	}
	// Take first 4 parts (64 bits) and add :: to indicate network prefix
	return strings.Join(parts[:4], ":") + "::"
}

// getIPv6InterfaceIdentifier extracts the interface identifier (last 64 bits) from an IPv6 address
func getIPv6InterfaceIdentifier(ipv6 string) string {
	if ipv6 == "" {
		return ""
	}
	// Split the IPv6 address into parts
	parts := strings.Split(ipv6, ":")
	if len(parts) < 4 {
		return ""
	}
	// Take last 4 parts (64 bits) and add :: prefix
	if len(parts) >= 8 {
		return "::" + strings.Join(parts[4:], ":")
	}
	// Handle compressed notation
	return ipv6
}

// ReplacePlaceholders replaces placeholders in expressions with actual values
// Returns the replaced string and an error if required placeholders cannot be replaced
func ReplacePlaceholders(expression string, ipv4, ipv6 string) (string, error) {
	replacer := strings.NewReplacer(
		"{{PUBLIC_IPV4}}", ipv4,
		"{{PUBLIC_IPV6}}", ipv6,
		"{{PUBLIC_IP}}", ipv4, // Default to IPv4
	)

	result := replacer.Replace(expression)

	// Track if we have missing placeholders
	var missingPlaceholders []string

	// Support {{PUBLIC_IPV4/24}} notation for CIDR blocks
	cidrRegex := regexp.MustCompile(`\{\{PUBLIC_IPV4/(\d+)\}\}`)
	result = cidrRegex.ReplaceAllStringFunc(result, func(match string) string {
		cidr := cidrRegex.FindStringSubmatch(match)[1]
		if ipv4 != "" {
			return fmt.Sprintf("%s/%s", ipv4, cidr)
		}
		missingPlaceholders = append(missingPlaceholders, match)
		return match
	})

	cidrRegex6 := regexp.MustCompile(`\{\{PUBLIC_IPV6/(\d+)\}\}`)
	result = cidrRegex6.ReplaceAllStringFunc(result, func(match string) string {
		cidr := cidrRegex6.FindStringSubmatch(match)[1]
		if ipv6 != "" {
			return fmt.Sprintf("%s/%s", ipv6, cidr)
		}
		missingPlaceholders = append(missingPlaceholders, match)
		return match
	})

	// Support {{PUBLIC_IPV6_NETWORK}} for network identifier (first 64 bits)
	networkRegex := regexp.MustCompile(`\{\{PUBLIC_IPV6_NETWORK\}\}`)
	if networkRegex.MatchString(result) {
		network := getIPv6NetworkIdentifier(ipv6)
		if network == "" {
			missingPlaceholders = append(missingPlaceholders, "{{PUBLIC_IPV6_NETWORK}}")
		} else {
			result = networkRegex.ReplaceAllString(result, network)
		}
	}

	// Support {{PUBLIC_IPV6_NETWORK/prefix}} for network identifier with custom prefix
	networkCIDRRegex := regexp.MustCompile(`\{\{PUBLIC_IPV6_NETWORK/(\d+)\}\}`)
	result = networkCIDRRegex.ReplaceAllStringFunc(result, func(match string) string {
		cidr := networkCIDRRegex.FindStringSubmatch(match)[1]
		network := getIPv6NetworkIdentifier(ipv6)
		if network != "" {
			// Remove trailing :: and add CIDR notation
			network = strings.TrimSuffix(network, "::")
			return fmt.Sprintf("%s::/%s", network, cidr)
		}
		missingPlaceholders = append(missingPlaceholders, match)
		return match
	})

	// Support {{PUBLIC_IPV6_INTERFACE}} for interface identifier (last 64 bits)
	interfaceRegex := regexp.MustCompile(`\{\{PUBLIC_IPV6_INTERFACE\}\}`)
	if interfaceRegex.MatchString(result) {
		interfaceID := getIPv6InterfaceIdentifier(ipv6)
		if interfaceID == "" {
			missingPlaceholders = append(missingPlaceholders, "{{PUBLIC_IPV6_INTERFACE}}")
		} else {
			result = interfaceRegex.ReplaceAllString(result, interfaceID)
		}
	}

	// Check for basic placeholders that might not have been replaced
	if ipv4 == "" && strings.Contains(result, "{{PUBLIC_IPV4}}") {
		missingPlaceholders = append(missingPlaceholders, "{{PUBLIC_IPV4}}")
	}
	if ipv6 == "" && strings.Contains(result, "{{PUBLIC_IPV6}}") {
		missingPlaceholders = append(missingPlaceholders, "{{PUBLIC_IPV6}}")
	}

	if len(missingPlaceholders) > 0 {
		return result, fmt.Errorf("unable to replace placeholders (missing IP addresses): %s", strings.Join(missingPlaceholders, ", "))
	}

	return result, nil
}

// doRequest performs an HTTP request to Cloudflare API
func (c *CloudflareClient) doRequest(ctx context.Context, method, path string, body interface{}) (*CloudflareResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var cfResp CloudflareResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !cfResp.Success {
		errMsgs := make([]string, len(cfResp.Errors))
		for i, e := range cfResp.Errors {
			errMsgs[i] = fmt.Sprintf("%s (code: %d)", e.Message, e.Code)
		}
		return nil, fmt.Errorf("cloudflare API error: %s", strings.Join(errMsgs, ", "))
	}

	return &cfResp, nil
}

// GetRuleset retrieves a ruleset by ID
func (c *CloudflareClient) GetRuleset(ctx context.Context, zoneID, rulesetID string) (*CloudflareRuleset, error) {
	path := fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID)
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var ruleset CloudflareRuleset
	if err := json.Unmarshal(resp.Result, &ruleset); err != nil {
		return nil, fmt.Errorf("failed to parse ruleset: %w", err)
	}

	return &ruleset, nil
}

// GetRule retrieves a specific rule from a ruleset
func (c *CloudflareClient) GetRule(ctx context.Context, zoneID, rulesetID, ruleID string) (*CloudflareRule, error) {
	ruleset, err := c.GetRuleset(ctx, zoneID, rulesetID)
	if err != nil {
		return nil, err
	}

	for _, rule := range ruleset.Rules {
		if rule.ID == ruleID || rule.Ref == ruleID {
			return &rule, nil
		}
	}

	return nil, fmt.Errorf("rule %s not found in ruleset", ruleID)
}

// CreateRule creates a new rule in a ruleset
func (c *CloudflareClient) CreateRule(ctx context.Context, zoneID, rulesetID string, rule CloudflareRule) (*CloudflareRule, error) {
	// Get current ruleset to append the rule
	ruleset, err := c.GetRuleset(ctx, zoneID, rulesetID)
	if err != nil {
		return nil, err
	}

	// Add new rule to the rules list
	ruleset.Rules = append(ruleset.Rules, rule)

	// Update the ruleset with the new rule
	path := fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID)
	resp, err := c.doRequest(ctx, http.MethodPut, path, map[string]interface{}{
		"rules": ruleset.Rules,
	})
	if err != nil {
		return nil, err
	}

	var updatedRuleset CloudflareRuleset
	if err := json.Unmarshal(resp.Result, &updatedRuleset); err != nil {
		return nil, fmt.Errorf("failed to parse updated ruleset: %w", err)
	}

	// Find and return the newly created rule
	if len(updatedRuleset.Rules) > 0 {
		return &updatedRuleset.Rules[len(updatedRuleset.Rules)-1], nil
	}

	return nil, fmt.Errorf("rule was not created")
}

// UpdateRule updates an existing rule
func (c *CloudflareClient) UpdateRule(ctx context.Context, zoneID, rulesetID, ruleID string, rule CloudflareRule) (*CloudflareRule, error) {
	path := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, rulesetID, ruleID)
	resp, err := c.doRequest(ctx, http.MethodPatch, path, rule)
	if err != nil {
		return nil, err
	}

	var updatedRule CloudflareRule
	if err := json.Unmarshal(resp.Result, &updatedRule); err != nil {
		return nil, fmt.Errorf("failed to parse updated rule: %w", err)
	}

	return &updatedRule, nil
}

// UpsertRule creates or updates a rule intelligently
func (c *CloudflareClient) UpsertRule(ctx context.Context, zoneID, rulesetID, ruleID string, rule CloudflareRule) (*CloudflareRule, bool, error) {
	// Check if rule exists
	existingRule, err := c.GetRule(ctx, zoneID, rulesetID, ruleID)

	if err != nil || existingRule == nil {
		// Rule doesn't exist, create it
		log.Infof("Creating new Cloudflare rule: %s", rule.Description)
		newRule, err := c.CreateRule(ctx, zoneID, rulesetID, rule)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create rule: %w", err)
		}
		return newRule, true, nil
	}

	// Rule exists, update it
	log.Infof("Updating existing Cloudflare rule: %s", rule.Description)
	updatedRule, err := c.UpdateRule(ctx, zoneID, rulesetID, ruleID, rule)
	if err != nil {
		return nil, false, fmt.Errorf("failed to update rule: %w", err)
	}
	return updatedRule, false, nil
}

var (
	cfZoneID    string
	cfRulesetID string
	cfRuleID    string
	cfAction    string
	cfDesc      string
	cfEnabled   bool
	cfExpr      string
	cfPosition  int
	cfIP        string
	cfIPv6      string
)

type publicIPFetcher func(ctx context.Context) (ipv4, ipv6 string, err error)

func resolvePublicIPs(ctx context.Context, ipv4Override, ipv6Override string, fetcher publicIPFetcher) (string, string, error) {
	if ipv4Override != "" {
		ip := net.ParseIP(strings.TrimSpace(ipv4Override))
		if ip == nil || ip.To4() == nil {
			return "", "", fmt.Errorf("invalid IPv4 address for --ip: %q", ipv4Override)
		}
	}
	if ipv6Override != "" {
		ip := net.ParseIP(strings.TrimSpace(ipv6Override))
		if ip == nil || ip.To4() != nil {
			return "", "", fmt.Errorf("invalid IPv6 address for --ipv6: %q", ipv6Override)
		}
	}

	if ipv4Override != "" || ipv6Override != "" {
		return strings.TrimSpace(ipv4Override), strings.TrimSpace(ipv6Override), nil
	}

	if fetcher == nil {
		return "", "", fmt.Errorf("no public IP fetcher provided")
	}
	return fetcher(ctx)
}

// CloudflareCmd represents the cloudflare command
var CloudflareCmd = &cobra.Command{
	Use:   "cloudflare",
	Short: i18n.T("Update Cloudflare security rules"),
	Long:  i18n.T("Create or update Cloudflare WAF rules with support for IP placeholders"),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Get API token from environment
		apiToken := os.Getenv("CF_AUTH_TOKEN")
		if apiToken == "" {
			apiToken = os.Getenv("CLOUDFLARE_API_TOKEN")
		}
		if apiToken == "" {
			return fmt.Errorf("CF_AUTH_TOKEN or CLOUDFLARE_API_TOKEN environment variable is required")
		}

		// Validate required flags
		if cfZoneID == "" || cfRulesetID == "" {
			return fmt.Errorf("zone-id and ruleset-id are required")
		}

		if cfAction == "" || cfExpr == "" {
			return fmt.Errorf("action and expression are required")
		}

		// Resolve public IPs (only when needed)
		usesDynamic := strings.Contains(cfExpr, "{{PUBLIC_")
		requireIPv4 := usesDynamic && (strings.Contains(cfExpr, "{{PUBLIC_IP}}") || strings.Contains(cfExpr, "{{PUBLIC_IPV4"))
		requireIPv6 := usesDynamic && strings.Contains(cfExpr, "{{PUBLIC_IPV6")

		var ipv4, ipv6 string
		if cfIP != "" || cfIPv6 != "" {
			log.Info("Using IP addresses provided via flags; skipping online lookup")
			resolvedV4, resolvedV6, err := resolvePublicIPs(ctx, cfIP, cfIPv6, utils.GetPublicIP)
			if err != nil {
				return err
			}
			ipv4, ipv6 = resolvedV4, resolvedV6
		} else if usesDynamic {
			log.Info("Fetching public IP addresses...")
			type ipPair struct{ v4, v6 string }
			pair, err := utils.Retry[ipPair](ctx, utils.RetryOptions{
				Attempts:  6,
				BaseDelay: 1 * time.Second,
				MaxDelay:  8 * time.Second,
				OnRetry: func(attempt int, nextDelay time.Duration, _ error) {
					if log != nil {
						log.Infof("Public IP not ready yet; retrying in %s (%d/%d)", nextDelay, attempt, 6)
					}
				},
				ExceededError: func(attempts int, _ error) error {
					var missing []string
					if requireIPv4 {
						missing = append(missing, "IPv4")
					}
					if requireIPv6 {
						missing = append(missing, "IPv6")
					}
					return fmt.Errorf("unable to determine required public IP(s) after %d attempt(s): %s", attempts, strings.Join(missing, ", "))
				},
			}, func(ctx context.Context) (ipPair, bool, error) {
				v4, v6, err := resolvePublicIPs(ctx, "", "", utils.GetPublicIP)
				if err != nil {
					return ipPair{}, false, err
				}
				missingV4 := requireIPv4 && strings.TrimSpace(v4) == ""
				missingV6 := requireIPv6 && strings.TrimSpace(v6) == ""
				if missingV4 || missingV6 {
					return ipPair{v4: v4, v6: v6}, true, nil
				}
				return ipPair{v4: v4, v6: v6}, false, nil
			})
			if err != nil {
				return err
			}
			ipv4, ipv6 = pair.v4, pair.v6
		}

		if ipv4 != "" {
			log.Infof("Public IPv4: %s", ipv4)
		}
		if ipv6 != "" {
			log.Infof("Public IPv6: %s", ipv6)
		}

		// Skip API call if IPs unchanged and rule configuration unchanged
		if cfSkipUnchanged {
			if lastCache, err := readLastCache(); err == nil {
				// Check if both IPs and rule configuration are unchanged
				ipsUnchanged := (!usesDynamic || (ipv4 == lastCache.IPv4 && ipv6 == lastCache.IPv6))
				ruleUnchanged := cfExpr == lastCache.Expression &&
					cfAction == lastCache.Action &&
					cfEnabled == lastCache.Enabled &&
					cfRuleID == lastCache.RuleID

				if ipsUnchanged && ruleUnchanged {
					log.Info("No changes detected (IPs and rule configuration unchanged); skipping Cloudflare API call")
					return nil
				}
			}
		}

		// Replace placeholders in expression
		expression, err := ReplacePlaceholders(cfExpr, ipv4, ipv6)
		if err != nil {
			return fmt.Errorf("failed to replace placeholders in expression: %w", err)
		}
		if expression != cfExpr {
			log.Info("Expression after placeholder replacement:")
			log.Info(expression)
		}

		// Create rule object
		rule := CloudflareRule{
			Action:      cfAction,
			Description: cfDesc,
			Enabled:     cfEnabled,
			Expression:  expression,
		}

		if cfPosition > 0 {
			rule.Position = &CloudflarePosition{
				Index: cfPosition,
			}
		}

		// Create Cloudflare client
		client := NewCloudflareClient(apiToken)

		// Upsert rule
		var result *CloudflareRule
		var created bool

		if cfRuleID != "" {
			result, created, err = client.UpsertRule(ctx, cfZoneID, cfRulesetID, cfRuleID, rule)
		} else {
			// No rule ID provided, always create
			result, err = client.CreateRule(ctx, cfZoneID, cfRulesetID, rule)
			created = true
		}

		if err != nil {
			return fmt.Errorf("failed to upsert rule: %w", err)
		}

		// Print result
		if created {
			log.Info("✓ Rule created successfully!")
		} else {
			log.Info("✓ Rule updated successfully!")
		}

		log.Infof("Rule ID: %s", result.ID)
		log.Infof("Description: %s", result.Description)
		log.Infof("Action: %s", result.Action)
		log.Infof("Enabled: %v", result.Enabled)

		// Persist current IPs and rule configuration for future change detection
		if cfSkipUnchanged {
			cache := &cloudflareCache{
				IPv4:       ipv4,
				IPv6:       ipv6,
				Expression: cfExpr,
				Action:     cfAction,
				Enabled:    cfEnabled,
				RuleID:     cfRuleID,
			}
			_ = writeCache(cache)
		}

		return nil
	},
}

func init() {
	CloudflareCmd.Flags().StringVar(&cfZoneID, "zone-id", "", "Cloudflare Zone ID (required)")
	CloudflareCmd.Flags().StringVar(&cfRulesetID, "ruleset-id", "", "Cloudflare Ruleset ID (required)")
	CloudflareCmd.Flags().StringVar(&cfRuleID, "rule-id", "", "Cloudflare Rule ID (updates an existing rule; omit to always create a new rule)")
	CloudflareCmd.Flags().StringVar(&cfAction, "action", "block", "Rule action (block, challenge, js_challenge, managed_challenge, etc.)")
	CloudflareCmd.Flags().StringVar(&cfDesc, "description", "", "Rule description (shown in Cloudflare UI)")
	CloudflareCmd.Flags().BoolVar(&cfEnabled, "enabled", true, "Enable or disable the rule")
	CloudflareCmd.Flags().StringVar(&cfIP, "ip", "", "Public IPv4 address to use (skips online lookup)")
	CloudflareCmd.Flags().StringVar(&cfIPv6, "ipv6", "", "Public IPv6 address to use (skips online lookup)")
	CloudflareCmd.Flags().StringVar(
		&cfExpr,
		"expression",
		"",
		"Rule expression (required). Supports placeholders: {{PUBLIC_IP}} (IPv4), {{PUBLIC_IPV4}}, {{PUBLIC_IPV6}}, {{PUBLIC_IPV4/24}}, {{PUBLIC_IPV6/64}}, {{PUBLIC_IPV6_NETWORK}}, {{PUBLIC_IPV6_NETWORK/64}}, {{PUBLIC_IPV6_INTERFACE}}. If a placeholder cannot be resolved (e.g., no IPv6), the command fails.",
	)
	CloudflareCmd.Flags().IntVar(&cfPosition, "position", 0, "Rule position index within the ruleset (0 keeps Cloudflare default)")
	CloudflareCmd.Flags().BoolVar(&cfSkipUnchanged, "skip-unchanged", true, "Skip Cloudflare API call when IPs and rule configuration are unchanged (uses a local cache)")

	CloudflareCmd.MarkFlagRequired("zone-id")
	CloudflareCmd.MarkFlagRequired("ruleset-id")
	CloudflareCmd.MarkFlagRequired("expression")
}

// --- IP change cache helpers ---

var cfSkipUnchanged bool

func cacheDir() string {
	// Prefer XDG cache if present, else ~/.nas-manager/cache
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "nas-manager")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".nas-manager", "cache")
	}
	// Fallback to current directory
	return "."
}

func cacheFilePath() string {
	return filepath.Join(cacheDir(), "cloudflare-ip.json")
}

type cloudflareCache struct {
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	Expression string `json:"expression"`
	Action     string `json:"action"`
	Enabled    bool   `json:"enabled"`
	RuleID     string `json:"rule_id"`
}

func readLastIPs() (string, string, error) {
	path := cacheFilePath()
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var s cloudflareCache
	if err := json.Unmarshal(b, &s); err != nil {
		return "", "", err
	}
	return s.IPv4, s.IPv6, nil
}

func readLastCache() (*cloudflareCache, error) {
	path := cacheFilePath()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s cloudflareCache
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeLastIPs(v4, v6 string) error {
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(cloudflareCache{IPv4: v4, IPv6: v6})
	return os.WriteFile(cacheFilePath(), b, 0o644)
}

func writeCache(cache *cloudflareCache) error {
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(cache)
	return os.WriteFile(cacheFilePath(), b, 0o644)
}
