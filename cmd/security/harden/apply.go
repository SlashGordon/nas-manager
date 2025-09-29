package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SlashGordon/nas-manager/internal/constants"
	"github.com/SlashGordon/nas-manager/internal/i18n"
	"github.com/SlashGordon/nas-manager/internal/utils"
)

func printLine(out *os.File, format string, args ...any) error {
	_, err := fmt.Fprintf(out, format+"\n", args...)
	return err
}

// ---------------- DSM ----------------

func ApplyDSMHardening() error {
	utils.PrintHeader(i18n.T(i18n.DSMHardeningTitle))

	config, err := os.ReadFile(constants.SynoSecurityScanConf)
	if err != nil {
		return nil // nothing to do
	}

	if strings.Contains(string(config), "enable_autoblock=yes") {
		return printLine(os.Stdout, "%s", i18n.T(i18n.DSMConfigured))
	}

	return handleDSMConfig(string(config))
}

func handleDSMConfig(config string) error {
	trusted := false
	choice := constants.ChoiceYes
	if !trusted {
		choice = PromptUser(i18n.T(i18n.DSMAutoBlock))
	}

	switch choice {
	case constants.ChoiceYes:
		if err := printLine(os.Stdout, "Auto-applying: %s", i18n.T(i18n.DSMAutoBlock)); err != nil {
			return err
		}
		return enableAutoBlock(config)

	case constants.ChoiceTrust:
		if err := printLine(os.Stdout, "  %s", i18n.T(i18n.TrustingRemaining)); err != nil {
			return err
		}
		return enableAutoBlock(config)

	case constants.ChoiceNo:
		return printLine(os.Stdout, "%s", i18n.T(i18n.DSMAutoBlockSkipped))
	}

	return nil
}

func enableAutoBlock(config string) error {
	newConfig := strings.ReplaceAll(config, "enable_autoblock=no", "enable_autoblock=yes")
	if err := os.WriteFile(constants.SynoSecurityScanConf, []byte(newConfig), 0600); err != nil {
		return printLine(os.Stderr, "%s: %v", i18n.T(i18n.DSMAutoBlockFailed), err)
	}
	if err := printLine(os.Stdout, "%s", i18n.T(i18n.DSMAutoBlockEnabled)); err != nil {
		return err
	}
	return printLine(os.Stdout, "\n%s", i18n.T(i18n.DSMRestart))
}

// ---------------- Services ----------------

func ApplyServiceHardening() error {
	utils.PrintHeader(i18n.T(i18n.ServiceHardeningTitle))

	services := []string{
		"pkgctl-AudioStation",
		"pkgctl-VideoStation",
		"pkgctl-PhotoStation",
		"pkgctl-SurveillanceStation",
	}

	trusted := false
	for _, service := range services {
		if err := handleService(service, trusted); err != nil {
			return err
		}
	}
	return nil
}

func handleService(service string, trusted bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	name := strings.TrimPrefix(service, "pkgctl-")
	if !serviceRunning(ctx, service) {
		return printLine(os.Stdout, i18n.T(i18n.ServiceAlreadyDisabled), name)
	}

	choice := constants.ChoiceYes
	if !trusted {
		choice = PromptUser(fmt.Sprintf("Disable %s service", name))
	}

	switch choice {
	case constants.ChoiceYes:
		if err := printLine(os.Stdout, i18n.T(i18n.ServiceDisabling), name); err != nil {
			return err
		}
		return disableService(ctx, service, name)

	case constants.ChoiceTrust:
		if err := printLine(os.Stdout, "  %s", i18n.T(i18n.TrustingRemaining)); err != nil {
			return err
		}
		return disableService(ctx, service, name)

	case constants.ChoiceNo:
		return printLine(os.Stdout, i18n.T(i18n.ServiceSkipped), name)
	}

	return nil
}

func serviceRunning(ctx context.Context, service string) bool {
	out, err := exec.CommandContext(ctx, "synoservice", "--status", service).Output()
	return err == nil && strings.Contains(string(out), "start")
}

func disableService(ctx context.Context, service, name string) error {
	if err := exec.CommandContext(ctx, "synoservice", "--disable", service).Run(); err != nil {
		return printLine(os.Stderr, i18n.T(i18n.ServiceFailed), name, err)
	}
	return printLine(os.Stdout, i18n.T(i18n.ServiceDisabled), name)
}
