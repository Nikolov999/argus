package cli

import (
	"adreview/internal/models"
	"adreview/internal/util"
	"fmt"
	"os"
)

func Execute(args []string) int {
	if len(args) < 2 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		printBanner()
		printUsage()
		return 0
	}

	printBanner()

	module := args[1]
	cfg, err := parseCommonFlags(args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	if cfg.Domain == "" {
		fmt.Fprintln(os.Stderr, "error: -d <domain> is required")
		return 1
	}
	if cfg.DC == "" {
		fmt.Fprintln(os.Stderr, "error: -dc <domain-controller> is required")
		return 1
	}

	cfg.BaseDN = util.DomainToBaseDN(cfg.Domain)
	cfg.LDAPURL = util.BuildLDAPURL(cfg.DC, cfg.UseLDAPS)

	switch module {
	case "enum":
		return RunEnum(cfg)
	case "kerb":
		return RunKerberos(cfg)
	case "misconfig":
		return RunMisconfig(cfg)
	case "adcs":
		return RunADCS(cfg)
	case "gpoenum":
		return RunGPO(cfg)
	case "trustaudit":
		return RunTrust(cfg)
	case "delegaudit":
		return RunDeleg(cfg)
	case "certsurface":
		return RunCert(cfg)
	case "adminscope":
		return RunAdminScope(cfg)
	case "lateralmap":
		return RunLateral(cfg)
	case "shareaudit":
		return RunShareAudit(cfg)
	case "aclaudit":
		return RunACLAudit(cfg)
	case "tierzero":
		return RunTierZero(cfg)
	case "sprawl":
		return RunSprawl(cfg)
	case "auto":
		return RunAuto(cfg)
	default:
		printUsage()
		return 1
	}
}

func defaultConfig() models.Config {
	return models.Config{
		UseLDAPS:       false,
		TimeoutSeconds: 15,
		Workers:        32,
	}
}

func printBanner() {
	fmt.Print(`
    ___    ____  ____  _______    _________ _       __
   /   |  / __ \/ __ \/ ____/ |  / /  _/ _ \ |     / /
  / /| | / / / / /_/ / __/  | | / // //  __/ | /| / /
 / ___ |/ /_/ / _, _/ /___  | |/ // // /\___| |/ |/ /
/_/  |_/_____/_/ |_/_____/  |___/___/_/      |__/|__/

        Active Directory Review Framework
                 by Bobo, EchoPentest
`)
}

func printUsage() {
	fmt.Println(`adreview <module> [options]

Modules:
  enum         Domain inventory counts
  kerb         Kerberos exposure review
  misconfig    Read-only misconfiguration review
  adcs         Basic AD CS review scaffold
  gpoenum      Group Policy Object inventory
  trustaudit   Domain trust inventory
  delegaudit   Delegation configuration review
  certsurface  Certificate template surface review
  adminscope   Privileged group scope review
  lateralmap   Remote management surface inventory
  shareaudit   SMB exposure inventory
  aclaudit     Delegation and protected-object ACL indicators
  tierzero     Tier 0 asset and identity inventory
  sprawl       Privilege sprawl review
  auto         Run core review

Common options:
  -d              Domain, for example corp.local
  -dc             Domain controller hostname or IP
  -ldaps          Use LDAPS
  -u              Bind username
  -p              Bind password
  --json          Write JSON report
  --html          Write HTML report
  --privileged-check
                  Restrict kerberos review output to privileged principals
  --password-age  Enable password age review
  --timeout       Network/LDAP timeout in seconds
  --workers       Concurrent workers for network-heavy modules`)
}
