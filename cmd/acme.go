package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/fs"
	"github.com/SlashGordon/nas-manager/internal/i18n"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/spf13/cobra"
)

var acmeCmd = &cobra.Command{
	Use:   "acme",
	Short: i18n.T(i18n.CmdACMEShort),
	Long:  i18n.T(i18n.CmdACMELong),
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: i18n.T(i18n.CmdACMEIssueShort),
	Run: func(_ *cobra.Command, _ []string) {
		config := getAcmeConfig()

		if config.CFToken == "" || config.Domain == "" || config.Email == "" {
			log.Error(i18n.T(i18n.ACMEError))
			os.Exit(1)
		}

		log.Infof(i18n.T(i18n.ACMEIssuing), config.Domain)

		if err := issueCertificate(config); err != nil {
			log.Errorf(i18n.T(i18n.ACMEFailed), err)
			os.Exit(1)
		}

		log.Infof(i18n.T(i18n.ACMESuccess), config.Domain)
	},
}

type AcmeConfig struct {
	Domain   string
	CertPath string
	Email    string
	CFToken  string
}

func getAcmeConfig() AcmeConfig {
	return AcmeConfig{
		Domain:   GetEnv("ACME_DOMAIN", ""),
		CertPath: GetEnv("ACME_CERT_PATH", "./cert"),
		Email:    GetEnv("ACME_EMAIL", ""),
		CFToken:  GetEnv("CF_API_TOKEN", ""),
	}
}

func issueCertificate(config AcmeConfig) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	user := &User{
		Email: config.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return err
	}

	if err := os.Setenv("CLOUDFLARE_DNS_API_TOKEN", config.CFToken); err != nil {
		return fmt.Errorf("failed to set environment variable: %w", err)
	}
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return err
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return fmt.Errorf("failed to set DNS provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{config.Domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	certPath := config.CertPath
	usingFallback := false

	// Try to create directory and test write permissions
	if err := fs.MkdirAll(certPath, 0750); err != nil {
		usingFallback = true
	} else {
		// Test write permissions by creating a temporary file
		testFile := filepath.Join(certPath, ".write_test")
		if err := fs.WriteFile(testFile, []byte("test"), 0600); err != nil {
			usingFallback = true
		} else {
			fs.Remove(testFile)
		}
	}

	if usingFallback {
		dateStr := time.Now().Format("2006-01-02")
		domainSafe := strings.ReplaceAll(config.Domain, ".", "_")
		certPath = fmt.Sprintf("./certs/%s-%s", domainSafe, dateStr)
		log.Warnf(i18n.T(i18n.ACMEPermissionDenied), config.CertPath, certPath)
		if err := fs.MkdirAll(certPath, 0750); err != nil {
			return fmt.Errorf("failed to create fallback directory: %w", err)
		}
	}

	// Write certificates
	files := map[string][]byte{
		config.Domain + ".key": certs.PrivateKey,
		config.Domain + ".cer": certs.Certificate,
		"fullchain.cer":        certs.Certificate,
		"ca.cer":               certs.IssuerCertificate,
		"privkey.pem":          certs.PrivateKey,
		"fullchain.pem":        certs.Certificate,
	}

	for filename, content := range files {
		perm := os.FileMode(constants.FilePermission0600)
		if writeErr := fs.WriteFile(filepath.Join(certPath, filename), content, perm); writeErr != nil {
			return fmt.Errorf("failed to write %s: %w", filename, writeErr)
		}
	}

	if usingFallback {
		log.Infof(i18n.T(i18n.ACMESaved), certPath)
		log.Infof(i18n.T(i18n.ACMECopy), config.CertPath)
		log.Infof("Run: sudo cp %s/* %s/", certPath, config.CertPath)
	} else {
		exec.Command(constants.SynoServiceCtlPath, "--reload", "nginx").Run()
	}

	return nil
}

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func init() {
	acmeCmd.AddCommand(issueCmd)
}
