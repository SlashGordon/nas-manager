package harden

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
)

// CheckCertificates checks the system certificate and returns a short hardening result.
func CheckCertificates() []HardeningResult {
	var results []HardeningResult

	content, err := os.ReadFile(constants.SynoCertificatePath)
	if err != nil {
		results = append(results, HardeningResult{
			Secure:         false,
			Message:        i18n.T(i18n.CertificateMissing),
			Recommendation: i18n.T(i18n.CertificateInstallRecommend),
		})
		return results
	}

	// try to decode PEM
	block, _ := pem.Decode(content)
	if block == nil {
		results = append(results, HardeningResult{
			Secure:         false,
			Message:        i18n.T(i18n.CertificateCannotVerify),
			Recommendation: i18n.T(i18n.CertificateRenewRecommend),
		})
		return results
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		results = append(results, HardeningResult{
			Secure:         false,
			Message:        i18n.T(i18n.CertificateCannotVerify),
			Recommendation: i18n.T(i18n.CertificateRenewRecommend),
		})
		return results
	}

	// check expiration
	if time.Now().After(cert.NotAfter) {
		results = append(results, HardeningResult{
			Secure:         false,
			Message:        i18n.T(i18n.CertificateExpired),
			Recommendation: i18n.T(i18n.CertificateRenewRecommend),
		})
		return results
	}

	results = append(results, HardeningResult{
		Secure:         true,
		Message:        i18n.T(i18n.CertificateFound),
		Recommendation: "",
	})

	return results
}
