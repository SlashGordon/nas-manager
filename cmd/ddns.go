package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/utils"
	"github.com/spf13/cobra"
)

var ddnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Cloudflare DDNS updater",
	Long:  "Update Cloudflare DNS records with current public IP",
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update DNS records",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = cmd, args
		config := getDDNSConfig()
		if config.CFToken == "" || config.CFZoneID == "" || config.CFRecordName == "" {
			fmt.Println("Error: CF_API_TOKEN, CF_ZONE_ID, and CF_RECORD_NAME environment variables are required")
			os.Exit(1)
		}

		currentIP, err := getCurrentIP(ddnsRecordType, ddnsIPv4, ddnsIPv6)
		if err != nil {
			fmt.Printf("Failed to get current IP: %v\n", err)
			os.Exit(1)
		}

		recordID, currentRecordIP, err := getDNSRecord(config, ddnsRecordType)
		if err != nil {
			fmt.Printf("Failed to get DNS record: %v\n", err)
			os.Exit(1)
		}

		if currentRecordIP == currentIP {
			fmt.Printf("%s unchanged (%s)\n", config.CFRecordName, currentIP)
			logDDNS(fmt.Sprintf("%s unchanged (%s)", config.CFRecordName, currentIP))
			return
		}

		if err := updateDNSRecord(config, recordID, ddnsRecordType, currentIP); err != nil {
			fmt.Printf("%s update failed: %v\n", config.CFRecordName, err)
			os.Exit(1)
		}

		fmt.Printf("Updated %s %s → %s\n", config.CFRecordName, currentRecordIP, currentIP)
		logDDNS(fmt.Sprintf("Updated %s %s → %s", config.CFRecordName, currentRecordIP, currentIP))
	},
}

var (
	ddnsRecordType string
	ddnsIPv4       string
	ddnsIPv6       string
)

type DDNSConfig struct {
	CFToken      string
	CFZoneID     string
	CFRecordName string
}

func getDDNSConfig() DDNSConfig {
	return DDNSConfig{
		CFToken:      os.Getenv("CF_API_TOKEN"),
		CFZoneID:     os.Getenv("CF_ZONE_ID"),
		CFRecordName: os.Getenv("CF_RECORD_NAME"),
	}
}

func getCurrentIP(recordType, ipv4Override, ipv6Override string) (string, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		recordType = "A"
	}
	if recordType != "A" && recordType != "AAAA" {
		return "", fmt.Errorf("invalid --type %q (must be A or AAAA)", recordType)
	}

	if ipv4Override != "" {
		ip := net.ParseIP(strings.TrimSpace(ipv4Override))
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 address for --ip: %q", ipv4Override)
		}
	}
	if ipv6Override != "" {
		ip := net.ParseIP(strings.TrimSpace(ipv6Override))
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("invalid IPv6 address for --ipv6: %q", ipv6Override)
		}
	}

	// If any override is provided, skip online lookup entirely.
	if ipv4Override != "" || ipv6Override != "" {
		if recordType == "A" {
			if strings.TrimSpace(ipv4Override) == "" {
				return "", fmt.Errorf("--type A requires --ip when skipping online lookup")
			}
			return strings.TrimSpace(ipv4Override), nil
		}
		if strings.TrimSpace(ipv6Override) == "" {
			return "", fmt.Errorf("--type AAAA requires --ipv6 when skipping online lookup")
		}
		return strings.TrimSpace(ipv6Override), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	ip, err := utils.Retry[string](ctx, utils.RetryOptions{
		Attempts:  6,
		BaseDelay: 1 * time.Second,
		MaxDelay:  8 * time.Second,
		ExceededError: func(_ int, _ error) error {
			if recordType == "A" {
				return fmt.Errorf("unable to determine public IPv4 after retries")
			}
			return fmt.Errorf("unable to determine public IPv6 after retries")
		},
	}, func(ctx context.Context) (string, bool, error) {
		v4, v6, err := utils.GetPublicIP(ctx)
		if err != nil {
			return "", false, err
		}
		if recordType == "A" {
			if strings.TrimSpace(v4) == "" {
				return "", true, nil
			}
			return v4, false, nil
		}
		if strings.TrimSpace(v6) == "" {
			return "", true, nil
		}
		return v6, false, nil
	})
	if err != nil {
		return "", err
	}
	return ip, nil
}

func updateDNSRecord(config DDNSConfig, recordID, recordType, newIP string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", config.CFZoneID, recordID)

	data := map[string]interface{}{
		"type":    recordType,
		"name":    config.CFRecordName,
		"content": newIP,
		"ttl":     1,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+config.CFToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if success, ok := result["success"].(bool); !ok || !success {
		return errors.New("API request was not successful")
	}

	return nil
}

func getDNSRecord(config DDNSConfig, recordType string) (string, string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=%s", config.CFZoneID, config.CFRecordName, recordType)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+config.CFToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	if resultArray, ok := result["result"].([]interface{}); ok && len(resultArray) > 0 {
		if record, ok := resultArray[0].(map[string]interface{}); ok {
			if id, ok := record["id"].(string); ok {
				if content, ok := record["content"].(string); ok {
					return id, content, nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("%s record %s not found", recordType, config.CFRecordName)
}

func logDDNS(message string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	logFile := fmt.Sprintf("%s/.ddns.log", homeDir)
	f, err := fs.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, message)

	fs.WriteFile(fmt.Sprintf("%s/.ddns_cache", homeDir), []byte(fmt.Sprintf("%s|%s", timestamp, message)), 0600)

	f.WriteString(logLine)
}

func init() {
	ddnsCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringVar(&ddnsRecordType, "type", "A", "DNS record type to update (A or AAAA)")
	updateCmd.Flags().StringVar(&ddnsIPv4, "ip", "", "Public IPv4 address to use (skips online lookup)")
	updateCmd.Flags().StringVar(&ddnsIPv6, "ipv6", "", "Public IPv6 address to use (skips online lookup)")
	rootCmd.AddCommand(ddnsCmd)
}
