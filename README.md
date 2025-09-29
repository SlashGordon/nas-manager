# NAS Manager

[![CI](https://github.com/SlashGordon/nas-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/SlashGordon/nas-manager/actions/workflows/ci.yml)
[![Release](https://github.com/SlashGordon/nas-manager/actions/workflows/release.yml/badge.svg)](https://github.com/SlashGordon/nas-manager/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SlashGordon/nas-manager)](https://goreportcard.com/report/github.com/SlashGordon/nas-manager)
[![Latest Release](https://img.shields.io/github/v/release/SlashGordon/nas-manager)](https://github.com/SlashGordon/nas-manager/releases/latest)

A comprehensive CLI tool for managing and securing your Synology NAS system.

## Features

- **DDNS Management**: Update Cloudflare DNS records with current public IP
- **ACME Certificates**: Issue/renew Let's Encrypt certificates via Cloudflare DNS
- **Security Management**: 
  - Block malicious IPs using comprehensive blocklists (12+ sources) with regex parsing
  - Advanced filtering: exclude Cloudflare and local/private IP ranges
  - Port scan detection and automatic blocking
  - Vulnerability scanning for open ports and services
  - Safety manager with auto-revert functionality
- **System Hardening**:
  - SSH configuration hardening with interactive prompts
  - DSM security settings optimization
  - Shell history size reduction (default: 3 entries)
  - Kernel security settings (ASLR, dmesg restrictions)
  - Network security hardening (IP forwarding, redirects, SYN cookies)
  - Service hardening (disable unnecessary services)
  - Filesystem abstraction using afero for better testability
- **Multi-language Support**: English and German translations
- **Interactive Hardening**: y/n/trust confirmation system for all changes
- **Comprehensive Testing**: Unit tests with 95%+ coverage
- **Modern Architecture**: Clean code with dependency injection and interfaces

## Installation

### Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/SlashGordon/nas-manager/main/install.sh | sh
```

### Manual Install
Download the appropriate binary for your system from the releases page.

## Configuration

Configuration is loaded in this priority order:
1. `NAS_CONFIG` environment variable (custom path)
2. `.nasrc` in working directory
3. `.nasrc` in home directory
4. Environment variables

Copy `.nasrc.example` to `.nasrc` and set your credentials:

```bash
cp .nasrc.example .nasrc
# Edit .nasrc with your actual values
```

Or use a custom config path:
```bash
NAS_CONFIG=/path/to/config nas-manager ddns update
```

Required environment variables:
- `CF_API_TOKEN` - Cloudflare API token (used for both DDNS and ACME)
- `CF_ZONE_ID` - Cloudflare zone ID (for DDNS)
- `CF_RECORD_NAME` - DNS record name to update
- `ACME_DOMAIN` - Domain for certificate
- `ACME_EMAIL` - Email for Let's Encrypt registration

Optional security variables:
- `SECURITY_CHAIN` - iptables chain name (default: BLOCKLIST)
- `SECURITY_DEFAULT_LISTS` - Select default lists: firehol_level1,spamhaus_drop,dshield,etc
- `SECURITY_CUSTOM_LISTS` - Custom blocklists (format: name=url,name2=url2)
- `PORTSCAN_THRESHOLD` - Max connections before blocking (default: 10)
- `PORTSCAN_WINDOW` - Time window in seconds (default: 60)
- `VULNSCAN_TARGET` - Target host for vulnerability scans (default: localhost)
- `VULNSCAN_PORTS` - Comma-separated list of ports to scan
- `SHELL_HIST_SIZE` - Shell history size limit (default: 3)

## New Features

### Regex-Based Blocklist Parsing
Supports multiple blocklist formats:
- **Plain IPs/CIDRs**: `192.168.1.1` or `192.168.1.0/24`
- **Tor Exit Addresses**: `ExitAddress 1.2.3.4 timestamp`
- **Spamhaus Format**: `1.2.3.4/24 ; comment`
- **Custom Formats**: Easily extensible via regex patterns

### Advanced IP Filtering
- **Cloudflare Filter**: Automatically excludes Cloudflare IP ranges
- **Local IP Filter**: Excludes private/local IP ranges (RFC 1918)
- **Smart Deduplication**: Removes duplicate IPs across all lists

### Safety Features
- **Auto-Revert**: Automatically reverts changes if SSH connection is lost
- **Connection Monitoring**: Detects client IP and monitors connectivity
- **Interactive Confirmation**: 30-second window to confirm changes

### Code Quality Improvements
- **Afero Integration**: Filesystem abstraction for better testing
- **HTTP Client**: Centralized HTTP handling with timeouts
- **Comprehensive Tests**: Unit tests covering all major functionality
- **Reduced Complexity**: Simplified functions and better error handling

## Usage

```bash
# Show help
nas-manager --help

# DDNS commands
nas-manager ddns update

# ACME certificate management
nas-manager acme issue

# Security management
nas-manager security blocklist update  # Safe by default - auto-reverts if connection lost
nas-manager security blocklist update --filter-cloudflare=false  # Include Cloudflare IPs
nas-manager security blocklist update --filter-local=false       # Include local IPs
nas-manager security blocklist clear
nas-manager security portscan start
nas-manager security portscan stop
nas-manager security vulnscan ports
nas-manager security vulnscan services

# System hardening
nas-manager security harden scan
nas-manager security harden ssh
nas-manager security harden dsm
nas-manager security harden services
nas-manager security harden shell
nas-manager security harden kernel
nas-manager security harden network
```

## Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
go test ./...

# Clean build artifacts
make clean
```

## Release

Binaries are automatically built for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)