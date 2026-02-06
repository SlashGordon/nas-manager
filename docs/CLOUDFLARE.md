# Cloudflare Security Rule Management

This command allows you to create or update Cloudflare WAF security rules with intelligent detection and support for dynamic IP placeholders.

## Features

- **Automatic Create/Update Detection**: Automatically determines whether to create a new rule or update an existing one
- **IP Placeholder Support**: Dynamically replace placeholders with your current public IP addresses
- **IPv4 and IPv6 Support**: Fetch and use both IPv4 and IPv6 addresses
- **CIDR Notation**: Support for CIDR blocks with placeholders
- **Cloudflare API Integration**: Full integration with Cloudflare's ruleset API

## Prerequisites

Set your Cloudflare API token as an environment variable:

```bash
export CF_AUTH_TOKEN="your-cloudflare-api-token"
# or
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"
```

## Usage

### Basic Usage

```bash
nas-manager security cloudflare \
  --zone-id="YOUR_ZONE_ID" \
  --ruleset-id="YOUR_RULESET_ID" \
  --action="block" \
  --description="Block non-trusted IPs" \
  --expression='ip.src in {1.2.3.4}'
```

### Update Existing Rule

```bash
nas-manager security cloudflare \
  --zone-id="YOUR_ZONE_ID" \
  --ruleset-id="YOUR_RULESET_ID" \
  --rule-id="YOUR_RULE_ID" \
  --action="block" \
  --description="my ip" \
  --expression='(not ip.src in {2001:db8:abcd:12::/64} and http.host wildcard "gitea.example.com")'
```

### Using IP Placeholders

The tool supports the following placeholders:

- `{{PUBLIC_IP}}` - Replaced with your current public IPv4 address
- `{{PUBLIC_IPV4}}` - Replaced with your current public IPv4 address
- `{{PUBLIC_IPV6}}` - Replaced with your current public IPv6 address
- `{{PUBLIC_IPV4/24}}` - Replaced with your IPv4 address + /24 CIDR notation
- `{{PUBLIC_IPV6/64}}` - Replaced with your IPv6 address + /64 CIDR notation
- `{{PUBLIC_IPV6_NETWORK}}` - Replaced with IPv6 network identifier (first 64 bits, e.g., `2001:db8:abcd:1234::`)
- `{{PUBLIC_IPV6_NETWORK/64}}` - Replaced with IPv6 network identifier + CIDR notation (e.g., `2001:db8:abcd:1234::/64`)
- `{{PUBLIC_IPV6_INTERFACE}}` - Replaced with IPv6 interface identifier (last 64 bits, e.g., `::5678:90ab:cdef:1234`)

#### Example: Allow Only Your Current IP

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --action="block" \
  --description="Block all except my IP" \
  --expression='not ip.src in {{{PUBLIC_IPV4}}}'
```

#### Example: Multiple Hosts with Dynamic IP

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --rule-id="your-rule-id" \
  --action="block" \
  --description="Protect internal services" \
  --expression='(http.host wildcard "gitea.example.com" and not ip.src in {{{PUBLIC_IPV4/24}}}) or (http.host wildcard "media.example.com" and not ip.src in {{{PUBLIC_IPV6/64}}})'
```

#### Example: Mixed Static and Dynamic IPs

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --action="block" \
  --description="Allow office and home IPs" \
  --expression='not ip.src in {{{PUBLIC_IPV4}} 203.0.113.0/24 198.51.100.0/24}'
```

#### Example: IPv6 Network-Based Access Control

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --action="block" \
  --description="Allow only my IPv6 network" \
  --expression='not ip.src in {{{PUBLIC_IPV6_NETWORK/64}}}'
```

#### Example: IPv6 Interface Identifier Matching

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --action="challenge" \
  --description="Challenge traffic from specific interface IDs" \
  --expression='ip.src in {{{PUBLIC_IPV6_INTERFACE}} ::1234:5678:90ab:cdef}'
```

### Command Options

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--zone-id` | Cloudflare Zone ID | Yes | - |
| `--ruleset-id` | Cloudflare Ruleset ID | Yes | - |
| `--rule-id` | Rule ID for updates (omit for create) | No | - |
| `--action` | Rule action (block, challenge, js_challenge, etc.) | Yes | block |
| `--description` | Human-readable description of the rule | No | - |
| `--enabled` | Whether the rule is enabled | No | true |
| `--expression` | Cloudflare filter expression | Yes | - |
| `--position` | Rule position index in the ruleset | No | 0 |
| `--skip-unchanged` | Skip API call when public IPs are unchanged (applies when using placeholders) | No | true |

## How It Works

1. **Fetch Public IPs**: The tool queries multiple IP services to get your current IPv4 and IPv6 addresses
2. **Replace Placeholders**: Any placeholders in your expression are replaced with actual IP addresses
3. **Skip When Unchanged (optional)**: If `--skip-unchanged` is enabled and your expression contains placeholders, the command compares current public IPv4/IPv6 to the last successful run and skips the API call if both are unchanged. Cache: `~/.nas-manager/cache/cloudflare-ip.json` (or `$XDG_CACHE_HOME/nas-manager`)
4. **Check Existing Rule**: If `--rule-id` is provided, the tool checks if the rule exists
5. **Create or Update**: 
   - If the rule doesn't exist or no rule ID is provided, a new rule is created
   - If the rule exists, it's updated with the new configuration
6. **Confirmation**: The tool displays the result with the rule ID and configuration

## Finding Your IDs

### Zone ID
1. Log in to your Cloudflare dashboard
2. Select your domain
3. The Zone ID is shown in the right sidebar under "API"

### Ruleset ID
```bash
# List all rulesets for a zone
curl -X GET "https://api.cloudflare.com/client/v4/zones/YOUR_ZONE_ID/rulesets" \
  -H "Authorization: Bearer $CF_AUTH_TOKEN" \
  -H "Content-Type: application/json"
```

### Rule ID
```bash
# List all rules in a ruleset
curl -X GET "https://api.cloudflare.com/client/v4/zones/YOUR_ZONE_ID/rulesets/YOUR_RULESET_ID" \
  -H "Authorization: Bearer $CF_AUTH_TOKEN" \
  -H "Content-Type: application/json"
```

## Examples from Real Use Cases

### Protect Internal Services from External Access

```bash
nas-manager security cloudflare \
  --zone-id="YOUR_ZONE_ID" \
  --ruleset-id="YOUR_RULESET_ID" \
  --rule-id="YOUR_RULE_ID" \
  --action="block" \
  --description="Protect internal services" \
  --expression='(not ip.src in {{{PUBLIC_IPV6/64}}} and http.host wildcard "gitea.example.com") or (http.host wildcard "media.example.com" and not ip.src in {{{PUBLIC_IPV6/64}}}) or (http.host wildcard "internal.example.com" and not ip.src in {{{PUBLIC_IPV6/64}}})'
```



### Rate Limiting by Country

```bash
nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --action="challenge" \
  --description="Challenge non-EU traffic" \
  --expression='not ip.geoip.country in {"DE" "FR" "IT" "ES"} and not ip.src in {{{PUBLIC_IPV4}}}'
```

## Troubleshooting

### API Token Issues
Ensure your API token has the following permissions:
- Zone.Zone Settings.Read
- Zone.Zone WAF.Edit

### Expression Syntax Errors
Test your expressions in the Cloudflare dashboard first before using them in the CLI.

### IP Detection Failures
If IP detection fails, the tool will warn you but continue. You can use static IPs in your expressions instead.

## Integration with Automation

### Cron Job to Update Rules Daily

```bash
#!/bin/bash
# update-cloudflare-rules.sh

export CF_AUTH_TOKEN="your-token"

nas-manager security cloudflare \
  --zone-id="your-zone-id" \
  --ruleset-id="your-ruleset-id" \
  --rule-id="your-rule-id" \
  --action="block" \
  --description="Auto-updated home IP protection" \
  --expression='not ip.src in {{{PUBLIC_IPV4/24}}}'
```

Add to crontab:
```
0 2 * * * /path/to/update-cloudflare-rules.sh >> /var/log/cloudflare-update.log 2>&1
```

### Dynamic DNS Integration

Combine with DDNS updates to keep your Cloudflare rules in sync with your dynamic IP:

```bash
#!/bin/bash
# After DDNS update, also update Cloudflare rules
nas-manager ddns update
nas-manager security cloudflare \
  --zone-id="$ZONE_ID" \
  --ruleset-id="$RULESET_ID" \
  --rule-id="$RULE_ID" \
  --action="block" \
  --skip-unchanged=true \
  --expression='not ip.src in {{{PUBLIC_IPV6_NETWORK/64}} {{PUBLIC_IPV4}}}'
```

## Skip Unchanged IPs

To avoid unnecessary Cloudflare API calls when your public IPs haven’t changed:

- Enable (default): `--skip-unchanged=true`
- Disable to force update: `--skip-unchanged=false`
- Works only when the expression contains dynamic placeholders like `{{PUBLIC_IPV4}}`, `{{PUBLIC_IPV6}}`, or `{{PUBLIC_IPV6_NETWORK/64}}`
- Cache file: `~/.nas-manager/cache/cloudflare-ip.json` (or `$XDG_CACHE_HOME/nas-manager`)

### Example

```bash
nas-manager security cloudflare \
  --zone-id="YOUR_ZONE_ID" \
  --ruleset-id="YOUR_RULESET_ID" \
  --rule-id="YOUR_RULE_ID" \
  --action="block" \
  --enabled=true \
  --skip-unchanged=true \
  --expression='not ip.src in {{{PUBLIC_IPV6_NETWORK/64}} {{PUBLIC_IPV4}}}'
```

---

## Zero Trust Access Policy Management

The `zerotrust-policy` subcommand allows you to update Zero Trust Access policies with dynamic IP support. It supports both **app-specific policies** (tied to a single application) and **reusable policies** (account-level policies that can be shared across applications).

### Features

- **Update Access Policies**: Modify existing Zero Trust Access policies
- **App-Specific & Reusable Policies**: Support for both policy types
- **Dynamic IP Support**: Same placeholder system as WAF rules for automatic IP updates
- **Multiple Rule Types**: Support for IP addresses, emails, and Access groups
- **Partial Updates**: Only update the fields you specify, preserving existing configuration

### Policy Types

- **App-Specific Policies**: Policies created within a specific application. Require `--app-id`.
- **Reusable Policies**: Account-level policies that can be shared across multiple applications. Use `--reusable` flag instead of `--app-id`.

### Usage

#### App-Specific Policy (Basic)

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --include-ip="192.168.1.0/24"
```

#### Reusable Policy (Account-Level)

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --reusable \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="{{PUBLIC_IPV6_NETWORK/64}}"
```

#### Dynamic IP with Placeholders

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="{{PUBLIC_IPV6_NETWORK/64}}"
```

#### Multiple Include Rules

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="10.0.0.0/8" \
  --include-email="admin@example.com" \
  --include-group="YOUR_ACCESS_GROUP_ID"
```

#### Update Policy Decision and Session Duration

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --decision="allow" \
  --session-duration="24h" \
  --include-ip="{{PUBLIC_IPV4}}"
```

#### With Manual IP Override

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --ip="203.0.113.50" \
  --ipv6="2001:db8::1" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="{{PUBLIC_IPV6_NETWORK/64}}"
```

### Command Options

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--account-id` | Cloudflare Account ID | Yes | - |
| `--app-id` | Zero Trust Access Application ID | Yes* | - |
| `--policy-id` | Access Policy ID to update | Yes | - |
| `--reusable` | Update a reusable policy (account-level) | No | false |
| `--name` | Policy name | No | (preserved) |
| `--decision` | Policy decision: allow, deny, non_identity, bypass | No | (preserved) |
| `--include-ip` | IP addresses/CIDRs to include (repeatable, supports placeholders) | No | - |
| `--exclude-ip` | IP addresses/CIDRs to exclude (repeatable, supports placeholders) | No | - |
| `--include-email` | Email addresses to include (repeatable) | No | - |
| `--include-group` | Access Group IDs to include (repeatable) | No | - |
| `--session-duration` | Session duration (e.g., '24h', '30m') | No | (preserved) |
| `--precedence` | Policy precedence (lower = higher priority) | No | (preserved) |
| `--ip` | Manual IPv4 override (skips online lookup) | No | - |
| `--ipv6` | Manual IPv6 override (skips online lookup) | No | - |

*`--app-id` is required for app-specific policies. Use `--reusable` instead for account-level reusable policies.

### Supported Placeholders

Same as WAF rules:
- `{{PUBLIC_IP}}` / `{{PUBLIC_IPV4}}` - Current public IPv4 address
- `{{PUBLIC_IPV6}}` - Current public IPv6 address
- `{{PUBLIC_IPV4/24}}` - IPv4 with CIDR notation
- `{{PUBLIC_IPV6/64}}` - IPv6 with CIDR notation
- `{{PUBLIC_IPV6_NETWORK/64}}` - IPv6 network prefix with CIDR

### Finding Your IDs

#### Account ID
1. Log in to your Cloudflare dashboard
2. Go to any domain
3. The Account ID is shown in the right sidebar under "API"

#### Application ID
```bash
curl -X GET "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/access/apps" \
  -H "Authorization: Bearer $CF_AUTH_TOKEN" \
  -H "Content-Type: application/json"
```

#### Policy ID (App-Specific)
```bash
curl -X GET "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/access/apps/YOUR_APP_ID/policies" \
  -H "Authorization: Bearer $CF_AUTH_TOKEN" \
  -H "Content-Type: application/json"
```

#### Policy ID (Reusable/Account-Level)
```bash
curl -X GET "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/access/policies" \
  -H "Authorization: Bearer $CF_AUTH_TOKEN" \
  -H "Content-Type: application/json"
```

### How to Know if Your Policy is Reusable

If you get error code 12130 "can not update reusable policies through this endpoint" when using `--app-id`, your policy is a **reusable policy**. Use `--reusable` flag instead.

### Real-World Examples

#### Protect Internal Application with Dynamic Home IP

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --decision="allow" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="{{PUBLIC_IPV6_NETWORK/64}}" \
  --include-ip="10.0.0.0/8"
```

#### Allow Specific Users and Your Home Network

```bash
nas-manager security cloudflare zerotrust-policy \
  --account-id="YOUR_ACCOUNT_ID" \
  --app-id="YOUR_APP_ID" \
  --policy-id="YOUR_POLICY_ID" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-email="user1@example.com" \
  --include-email="user2@example.com"
```

#### Automation Script for Dynamic IP Updates

```bash
#!/bin/bash
# update-zerotrust-policy.sh

export CF_AUTH_TOKEN="your-token"

nas-manager security cloudflare zerotrust-policy \
  --account-id="$ACCOUNT_ID" \
  --app-id="$APP_ID" \
  --policy-id="$POLICY_ID" \
  --include-ip="{{PUBLIC_IPV4}}" \
  --include-ip="{{PUBLIC_IPV6_NETWORK/64}}"
```

Add to crontab:
```
*/30 * * * * /path/to/update-zerotrust-policy.sh >> /var/log/zerotrust-update.log 2>&1
```
