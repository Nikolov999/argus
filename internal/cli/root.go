package cli

import (
	"argus/internal/models"
	"argus/internal/util"
	"fmt"
	"os"
	"strings"
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
	case "privmap":
	        return RunPrivMap(cfg)
	case "aclexposure":
		return RunACLExposure(cfg)
	case "blast":
		return RunBlast(cfg)
	case "adminsd":
		return RunAdminSD(cfg)
	case "serviceimpact":
		return RunServiceImpact(cfg)
	case "dcattacksurface":
		return RunDCAttackSurface(cfg)
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
	lines := []string{
		`      █████╗ ██████╗  ██████╗ ██╗   ██╗ ██████╗         ╭─────────╮`,
		`     ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝         │ ╭─────╮ │`,
		`     ███████║██████╔╝██║  ███╗██║   ██║╚█████╗          ││ ◉   ◉ ││`,
		`     ██╔══██║██╔══██╗██║   ██║██║   ██║ ╚═══██╗         ││   ◡   ││`,
		`     ██║  ██║██║  ██║╚██████╔╝╚██████╔╝██████╔╝         │ ╰─────╯ │`,
		`     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝          ╰─────────╯`,
		`                    Active Directory Visibility Framework          `,
		`                           By Bobo, EchoPentest                    `,
	}

	start := [3]int{116, 58, 255}
	end := [3]int{214, 128, 255}
	reset := "\x1b[0m"

	for _, line := range lines {
		fmt.Println(applyGradient(line, start, end) + reset)
	}

	fmt.Println()
}

func applyGradient(s string, start, end [3]int) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	if len(runes) == 1 {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s", start[0], start[1], start[2], s)
	}

	var b strings.Builder
	last := len(runes) - 1

	for i, r := range runes {
		rr := start[0] + (end[0]-start[0])*i/last
		gg := start[1] + (end[1]-start[1])*i/last
		bb := start[2] + (end[2]-start[2])*i/last
		b.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm%c", rr, gg, bb, r))
	}

	return b.String()
}

func printUsage() {
	fmt.Println(`argus <module> [options]

Modules:

 Inventory:
   enum            Domain inventory counts
   tierzero        Tier 0 asset and identity inventory
   gpoenum         Group Policy Object inventory
   trustaudit      Domain trust inventory
 Exposure:
   kerb            Kerberos exposure review
   misconfig       Read-only misconfiguration review
   shareaudit      SMB exposure inventory
   lateralmap      Remote management surface inventory
   aclexposure     Dangerous ACL rights exposure review
 Privilege:
   sprawl          Privilege sprawl review
   privmap         Privileged group membership map
   adminscope      Privileged group scope review
   blast           Defender-oriented blast radius prioritization
   adminsd         AdminSDHolder and SDProp drift review
   serviceimpact   Service account privilege and dependency review
   dcattacksurface Domain controller exposure inventory
 Delegation and ACLs:
   aclaudit        Delegation and protected-object ACL indicators
   delegaudit      Delegation configuration review
 PKI:
   adcs            Basic AD CS review scaffold
   certsurface     Certificate template surface review
 Core Review:
   auto            Run core review
  

Common options:
  -d                  Domain, for example corp.local
  -dc                 Domain controller hostname or IP
  -ldaps              Use LDAPS
  -u                  Bind username
  -p                  Bind password
  --json              Write JSON report
  --html              Write HTML report
  --privileged-check  Restrict kerberos review output to privileged principals
  --privileged-only   Restrict ACL exposure review to high-value targets
  --password-age      Enable password age review
  --timeout           Network/LDAP timeout in seconds
  --workers           Concurrent workers for network-heavy modules
  --admin-name-regex  Regex used by privmap to suppress expected admin naming`)
}
