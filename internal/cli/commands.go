package cli

import (
	"adreview/internal/audit"
	ldapclient "adreview/internal/ldap"
	"adreview/internal/models"
	"adreview/internal/report"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func parseCommonFlags(args []string) (models.Config, error) {
	cfg := defaultConfig()

	fs := flag.NewFlagSet("adreview", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&cfg.Domain, "d", "", "domain")
	fs.StringVar(&cfg.DC, "dc", "", "domain controller")
	fs.BoolVar(&cfg.UseLDAPS, "ldaps", false, "use LDAPS")
	fs.StringVar(&cfg.Username, "u", "", "bind username")
	fs.StringVar(&cfg.Password, "p", "", "bind password")
	fs.StringVar(&cfg.JSONOut, "json", "", "json output path")
	fs.StringVar(&cfg.HTMLOut, "html", "", "html output path")
	fs.BoolVar(&cfg.PrivilegedOnly, "privileged-check", false, "show privileged principals only")
	fs.BoolVar(&cfg.PasswordAge, "password-age", false, "enable password age review")
	fs.IntVar(&cfg.TimeoutSeconds, "timeout", 15, "timeout seconds")
	fs.IntVar(&cfg.Workers, "workers", 32, "concurrent workers")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func RunEnum(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	users, err := client.CountByFilter("(&(objectCategory=person)(objectClass=user))")
	if err != nil {
		return fail(err)
	}
	groups, err := client.CountByFilter("(objectClass=group)")
	if err != nil {
		return fail(err)
	}
	computers, err := client.CountByFilter("(objectClass=computer)")
	if err != nil {
		return fail(err)
	}

	data := models.EnumSummary{Users: users, Groups: groups, Computers: computers}

	fmt.Println("AD INVENTORY")
	fmt.Println()
	fmt.Printf("Users: %d\n", data.Users)
	fmt.Printf("Groups: %d\n", data.Groups)
	fmt.Printf("Computers: %d\n", data.Computers)

	return emitArtifacts("enum", cfg, data)
}

func RunKerberos(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	users, err := client.SearchUsers()
	if err != nil {
		return fail(err)
	}

	data := audit.KerberosReview(cfg, users)

	fmt.Println("KERBEROS SECURITY REVIEW")
	fmt.Println()
	printKerbSection("ACCOUNTS WITH PREAUTH DISABLED", data.PreAuthDisabled)
	printKerbSection("SERVICE ACCOUNTS WITH SPNs", data.SPNAccounts)
	printKerbSection("PRIVILEGED ACCOUNTS WITH SPNs", data.PrivilegedSPNAccounts)
	printKerbSection("LEGACY ENCRYPTION TYPES ENABLED", data.LegacyEncryption)
	if cfg.PasswordAge {
		printKerbSection("PASSWORD AGE REVIEW", data.PasswordAgeReview)
	}

	return emitArtifacts("kerb", cfg, data)
}

func RunMisconfig(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	users, err := client.SearchUsers()
	if err != nil {
		return fail(err)
	}

	data := audit.MisconfigReview(users)

	fmt.Println("MISCONFIGURATION REVIEW")
	fmt.Println()
	for _, f := range data.Findings {
		fmt.Printf("[%s] %s\n", f.Severity, f.Title)
		fmt.Printf("Category: %s\n", f.Category)
		fmt.Printf("Why it matters: %s\n", f.Description)
		fmt.Printf("Remediation: %s\n\n", f.Remediation)
	}

	return emitArtifacts("misconfig", cfg, data)
}

func RunADCS(cfg models.Config) int {
	data := audit.ADCSReview()

	fmt.Println("AD CS REVIEW")
	fmt.Println()

	if len(data.Templates) == 0 {
		fmt.Println("No templates returned in current review scope.")
	} else {
		for _, t := range data.Templates {
			fmt.Printf("Template: %s\n", t.Name)
			fmt.Printf("Flags: %s\n", strings.Join(t.Flags, ", "))
			fmt.Printf("Risk Summary: %s\n\n", t.RiskSummary)
		}
	}

	return emitArtifacts("adcs", cfg, data)
}

func RunAuto(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	type countResult struct {
		name  string
		value int
		err   error
	}
	ch := make(chan countResult, 3)

	go func() {
		v, e := client.CountByFilter("(&(objectCategory=person)(objectClass=user))")
		ch <- countResult{name: "users", value: v, err: e}
	}()
	go func() {
		v, e := client.CountByFilter("(objectClass=group)")
		ch <- countResult{name: "groups", value: v, err: e}
	}()
	go func() {
		v, e := client.CountByFilter("(objectClass=computer)")
		ch <- countResult{name: "computers", value: v, err: e}
	}()

	var users, groups, computers int
	for i := 0; i < 3; i++ {
		r := <-ch
		if r.err != nil {
			return fail(r.err)
		}
		switch r.name {
		case "users":
			users = r.value
		case "groups":
			groups = r.value
		case "computers":
			computers = r.value
		}
	}

	userRecords, err := client.SearchUsers()
	if err != nil {
		return fail(err)
	}

	data := models.AutoResult{
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
		Enum:        models.EnumSummary{Users: users, Groups: groups, Computers: computers},
		Kerberos:    audit.KerberosReview(cfg, userRecords),
		Misconfig:   audit.MisconfigReview(userRecords),
		ADCS:        audit.ADCSReview(),
	}

	fmt.Println("ADREVIEW EXECUTIVE SUMMARY")
	fmt.Println()
	fmt.Printf("Users: %d\n", data.Enum.Users)
	fmt.Printf("Groups: %d\n", data.Enum.Groups)
	fmt.Printf("Computers: %d\n", data.Enum.Computers)
	fmt.Printf("Pre-auth disabled: %d\n", len(data.Kerberos.PreAuthDisabled))
	fmt.Printf("SPN accounts: %d\n", len(data.Kerberos.SPNAccounts))
	fmt.Printf("Privileged SPN accounts: %d\n", len(data.Kerberos.PrivilegedSPNAccounts))
	fmt.Printf("Legacy encryption review items: %d\n", len(data.Kerberos.LegacyEncryption))
	fmt.Printf("Misconfiguration findings: %d\n", len(data.Misconfig.Findings))
	fmt.Printf("AD CS templates reviewed: %d\n", len(data.ADCS.Templates))

	return emitArtifacts("auto", cfg, data)
}

func RunGPO(cfg models.Config) int {
	if cfg.Username == "" || cfg.Password == "" {
		return fail(fmt.Errorf("gpoenum requires -u and -p"))
	}

	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	gpos, err := client.SearchGPOs()
	if err != nil {
		return fail(err)
	}

	result := audit.GPOEnumReview(gpos)

	fmt.Println("GPO ENUMERATION")
	fmt.Println()

	if len(result.GPOs) == 0 {
		fmt.Println("none found")
		return emitArtifacts("gpoenum", cfg, result)
	}

	fmt.Printf("Total: %d | Info: %d | Low: %d | Medium: %d | High: %d | Critical: %d\n\n",
		result.Summary["total"], result.Summary["info"], result.Summary["low"],
		result.Summary["medium"], result.Summary["high"], result.Summary["critical"])

	for _, g := range result.GPOs {
		fmt.Printf("[%s] %s\n", g.Severity, g.Name)
		fmt.Printf("GUID: %s\n", g.GUID)
		fmt.Printf("Path: %s\n", g.Path)
		fmt.Printf("Version: %s\n", g.Version)
		fmt.Printf("Changed: %s\n", g.Changed)
		fmt.Printf("Flags: %s\n", g.Flags)
		fmt.Printf("Notes: %s\n\n", g.Description)
	}

	return emitArtifacts("gpoenum", cfg, result)
}

func RunTrust(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	trusts, err := client.SearchTrusts()
	if err != nil {
		return fail(err)
	}

	result := audit.TrustAudit(trusts)

	fmt.Println("DOMAIN TRUSTS")
	fmt.Println()

	if len(result.Trusts) == 0 {
		fmt.Println("none found")
		return emitArtifacts("trustaudit", cfg, result)
	}

	for _, t := range result.Trusts {
		fmt.Printf("%s\n", t.Partner)
		if t.FlatName != "" {
			fmt.Printf("Flat Name: %s\n", t.FlatName)
		}
		fmt.Printf("Direction: %s\n", t.Direction)
		fmt.Printf("Type: %s\n\n", t.Type)
	}

	return emitArtifacts("trustaudit", cfg, result)
}

func RunDeleg(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	principals, err := client.SearchDelegationPrincipals()
	if err != nil {
		return fail(err)
	}

	result := audit.DelegAudit(principals)

	fmt.Println("DELEGATION REVIEW")
	fmt.Println()
	printDelegSection("UNCONSTRAINED DELEGATION", result.Unconstrained)
	printDelegSection("CONSTRAINED DELEGATION", result.Constrained)
	printDelegSection("RESOURCE-BASED CONSTRAINED DELEGATION", result.ResourceBased)

	return emitArtifacts("delegaudit", cfg, result)
}

func RunCert(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	templates, err := client.SearchCertTemplates()
	if err != nil {
		return fail(err)
	}

	result := audit.CertSurface(templates)

	fmt.Println("CERTIFICATE TEMPLATE SURFACE")
	fmt.Println()

	if len(result.Templates) == 0 {
		fmt.Println("none found")
		return emitArtifacts("certsurface", cfg, result)
	}

	for _, t := range result.Templates {
		name := t.DisplayName
		if name == "" {
			name = t.Name
		}
		fmt.Printf("%s\n", name)
		if len(t.EKUs) > 0 {
			fmt.Printf("EKUs: %s\n", strings.Join(t.EKUs, ", "))
		}
		fmt.Printf("Risk Summary: %s\n\n", t.RiskSummary)
	}

	return emitArtifacts("certsurface", cfg, result)
}

func RunAdminScope(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	groups, err := client.SearchPrivilegedGroups()
	if err != nil {
		return fail(err)
	}

	result := audit.AdminScope(groups)

	fmt.Println("ADMIN PRIVILEGE SCOPE")
	fmt.Println()

	if len(result.Groups) == 0 {
		fmt.Println("none found")
		return emitArtifacts("adminscope", cfg, result)
	}

	for _, g := range result.Groups {
		fmt.Printf("%s\n", g.Name)
		fmt.Printf("Members: %d\n", g.MemberCount)
		for _, m := range g.Members {
			fmt.Printf("  - %s\n", m)
		}
		fmt.Println()
	}

	return emitArtifacts("adminscope", cfg, result)
}

func RunLateral(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	computers, err := client.SearchComputers()
	if err != nil {
		return fail(err)
	}

	result := audit.LateralMap(cfg, computers)

	fmt.Println("REMOTE MANAGEMENT SURFACE MAP")
	fmt.Println()

	if len(result.Targets) == 0 {
		fmt.Println("none found")
		return emitArtifacts("lateralmap", cfg, result)
	}

	for _, t := range result.Targets {
		fmt.Printf("%s\n", t.Host)
		for _, svc := range t.Services {
			fmt.Printf("  -> %s\n", svc)
		}
		fmt.Println()
	}

	return emitArtifacts("lateralmap", cfg, result)
}

func RunShareAudit(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	computers, err := client.SearchComputers()
	if err != nil {
		return fail(err)
	}

	result := audit.ShareAudit(cfg, computers)

	fmt.Println("SMB SHARE INVENTORY")
	fmt.Println()

	if len(result.Shares) == 0 {
		fmt.Println("none found")
		return emitArtifacts("shareaudit", cfg, result)
	}

	for _, s := range result.Shares {
		fmt.Printf("%s\n", s.Host)
		fmt.Printf("SMB Reachable: %t\n", s.SMBReachable)
		for _, n := range s.Notes {
			fmt.Printf("  - %s\n", n)
		}
		fmt.Println()
	}

	return emitArtifacts("shareaudit", cfg, result)
}

func RunACLAudit(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	targets, err := client.SearchACLTargets()
	if err != nil {
		return fail(err)
	}

	result := audit.ACLAudit(targets)

	fmt.Println("ACL AUDIT")
	fmt.Println()

	if len(result.Findings) == 0 {
		fmt.Println("none found")
		return emitArtifacts("aclaudit", cfg, result)
	}

	for _, f := range result.Findings {
		fmt.Printf("[%s] %s (%s)\n", f.Severity, f.Object, f.ObjectType)
		fmt.Printf("Principal: %s\n", f.Principal)
		fmt.Printf("Right: %s\n", f.Right)
		fmt.Printf("Why it matters: %s\n", f.Note)
		fmt.Printf("Remediation: %s\n\n", f.Remediation)
	}

	return emitArtifacts("aclaudit", cfg, result)
}

func RunTierZero(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	computers, err := client.SearchComputers()
	if err != nil {
		return fail(err)
	}
	groups, err := client.SearchPrivilegedGroups()
	if err != nil {
		return fail(err)
	}
	users, err := client.SearchUsers()
	if err != nil {
		return fail(err)
	}
	enrollmentServices, err := client.SearchEnrollmentServices()
	if err != nil {
		return fail(err)
	}

	result := audit.TierZeroInventory(cfg, computers, groups, users, enrollmentServices)

	fmt.Println("TIER ZERO INVENTORY")
	fmt.Println()

	if len(result.Assets) == 0 {
		fmt.Println("none found")
		return emitArtifacts("tierzero", cfg, result)
	}

	for _, a := range result.Assets {
		fmt.Printf("[%s] %s\n", a.Category, a.Name)
		if a.Detail != "" {
			fmt.Printf("Detail: %s\n", a.Detail)
		}
		fmt.Println()
	}

	return emitArtifacts("tierzero", cfg, result)
}

func RunSprawl(cfg models.Config) int {
	client, err := ldapclient.New(cfg)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	groups, err := client.SearchPrivilegedGroups()
	if err != nil {
		return fail(err)
	}

	result := audit.SprawlReview(groups)

	fmt.Println("PRIVILEGE SPRAWL REVIEW")
	fmt.Println()

	if len(result.Findings) == 0 {
		fmt.Println("none found")
		return emitArtifacts("sprawl", cfg, result)
	}

	for _, f := range result.Findings {
		fmt.Printf("[%s] %s\n", f.Severity, f.Category)
		fmt.Printf("Object: %s\n", f.Object)
		fmt.Printf("Finding: %s\n", f.Description)
		fmt.Printf("Remediation: %s\n\n", f.Remediation)
	}

	return emitArtifacts("sprawl", cfg, result)
}

func printKerbSection(title string, items []models.KerberosFinding) {
	fmt.Printf("[%s]\n", title)
	if len(items) == 0 {
		fmt.Println("none found")
		fmt.Println()
		return
	}

	for _, i := range items {
		if len(i.SPNs) == 0 {
			fmt.Println(i.SAMAccountName)
			continue
		}
		fmt.Printf("%s\tSPN: %s\n", i.SAMAccountName, strings.Join(i.SPNs, ", "))
	}
	fmt.Println()
}

func printDelegSection(title string, items []models.DelegationFinding) {
	fmt.Printf("[%s]\n", title)
	if len(items) == 0 {
		fmt.Println("none found")
		fmt.Println()
		return
	}

	for _, i := range items {
		fmt.Println(i.Principal)
		fmt.Printf("Reason: %s\n", i.Reason)
		if len(i.Targets) > 0 {
			fmt.Printf("Targets: %s\n", strings.Join(i.Targets, ", "))
		}
		fmt.Println()
	}
}

func emitArtifacts(module string, cfg models.Config, data interface{}) int {
	envelope := models.ReportEnvelope{
		GeneratedAt: time.Now().UTC(),
		Module:      module,
		Config:      cfg,
		Data:        data,
	}

	if cfg.JSONOut != "" {
		if err := report.WriteJSON(cfg.JSONOut, envelope); err != nil {
			return fail(err)
		}
		fmt.Println("JSON report written to", cfg.JSONOut)
	}

	if cfg.HTMLOut != "" {
		if err := report.WriteHTML(cfg.HTMLOut, module, cfg, data); err != nil {
			return fail(err)
		}
		fmt.Println("HTML report written to", cfg.HTMLOut)
	}

	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}
