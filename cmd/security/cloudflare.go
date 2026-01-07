package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
func ReplacePlaceholders(expression string, ipv4, ipv6 string) string {
	replacer := strings.NewReplacer(
		"{{PUBLIC_IPV4}}", ipv4,
		"{{PUBLIC_IPV6}}", ipv6,
		"{{PUBLIC_IP}}", ipv4, // Default to IPv4
	)

	result := replacer.Replace(expression)

	// Support {{PUBLIC_IPV4/24}} notation for CIDR blocks
	cidrRegex := regexp.MustCompile(`\{\{PUBLIC_IPV4/(\d+)\}\}`)
	result = cidrRegex.ReplaceAllStringFunc(result, func(match string) string {
		cidr := cidrRegex.FindStringSubmatch(match)[1]
		if ipv4 != "" {
			return fmt.Sprintf("%s/%s", ipv4, cidr)
		}
		return match
	})

	cidrRegex6 := regexp.MustCompile(`\{\{PUBLIC_IPV6/(\d+)\}\}`)
	result = cidrRegex6.ReplaceAllStringFunc(result, func(match string) string {
		cidr := cidrRegex6.FindStringSubmatch(match)[1]
		if ipv6 != "" {
			return fmt.Sprintf("%s/%s", ipv6, cidr)
		}
		return match
	})

	// Support {{PUBLIC_IPV6_NETWORK}} for network identifier (first 64 bits)
	networkRegex := regexp.MustCompile(`\{\{PUBLIC_IPV6_NETWORK\}\}`)
	result = networkRegex.ReplaceAllString(result, getIPv6NetworkIdentifier(ipv6))

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
		return match
	})

	// Support {{PUBLIC_IPV6_INTERFACE}} for interface identifier (last 64 bits)
	interfaceRegex := regexp.MustCompile(`\{\{PUBLIC_IPV6_INTERFACE\}\}`)
	result = interfaceRegex.ReplaceAllString(result, getIPv6InterfaceIdentifier(ipv6))

	return result
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
)

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

		// Get public IPs
		log.Info("Fetching public IP addresses...")
		ipv4, ipv6, err := utils.GetPublicIP(ctx)
		if err != nil {
			log.Warnf("Failed to get public IPs: %v", err)
		} else {
			if ipv4 != "" {
				log.Infof("Public IPv4: %s", ipv4)
			}
			if ipv6 != "" {
				log.Infof("Public IPv6: %s", ipv6)
			}
		}

		// Replace placeholders in expression
		expression := ReplacePlaceholders(cfExpr, ipv4, ipv6)
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

		return nil
	},
}

func init() {
	CloudflareCmd.Flags().StringVar(&cfZoneID, "zone-id", "", "Cloudflare Zone ID (required)")
	CloudflareCmd.Flags().StringVar(&cfRulesetID, "ruleset-id", "", "Cloudflare Ruleset ID (required)")
	CloudflareCmd.Flags().StringVar(&cfRuleID, "rule-id", "", "Cloudflare Rule ID (for update)")
	CloudflareCmd.Flags().StringVar(&cfAction, "action", "block", "Rule action (block, challenge, js_challenge, etc.)")
	CloudflareCmd.Flags().StringVar(&cfDesc, "description", "", "Rule description")
	CloudflareCmd.Flags().BoolVar(&cfEnabled, "enabled", true, "Enable the rule")
	CloudflareCmd.Flags().StringVar(&cfExpr, "expression", "", "Rule expression (required, supports {{PUBLIC_IP}}, {{PUBLIC_IPV4}}, {{PUBLIC_IPV6}} placeholders)")
	CloudflareCmd.Flags().IntVar(&cfPosition, "position", 0, "Rule position index (0 for default)")

	CloudflareCmd.MarkFlagRequired("zone-id")
	CloudflareCmd.MarkFlagRequired("ruleset-id")
	CloudflareCmd.MarkFlagRequired("expression")
}
