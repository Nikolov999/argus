package report

import (
	"adreview/internal/models"
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

type htmlView struct {
	GeneratedAt string
	Module      string
	Domain      string
	DC          string
	Content     template.HTML
}

func WriteHTML(path string, module string, cfg models.Config, data interface{}) error {
	content := buildModuleHTML(module, data)

	tpl := `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>adreview report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:40px;color:#222}
h1,h2,h3{margin-bottom:8px}
.card{border:1px solid #ddd;border-radius:8px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%;margin-top:10px}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
th{background:#f6f6f6}
</style>
</head>
<body>
<h1>adreview</h1>
<div class="card">
  <div><strong>Generated:</strong> {{.GeneratedAt}}</div>
  <div><strong>Module:</strong> {{.Module}}</div>
  <div><strong>Domain:</strong> {{.Domain}}</div>
  <div><strong>Domain Controller:</strong> {{.DC}}</div>
</div>
{{.Content}}
</body>
</html>`

	view := htmlView{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Module:      module,
		Domain:      cfg.Domain,
		DC:          cfg.DC,
		Content:     template.HTML(content),
	}

	var buf bytes.Buffer
	if err := template.Must(template.New("report").Parse(tpl)).Execute(&buf, view); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}

func buildModuleHTML(module string, data interface{}) string {
	switch x := data.(type) {
	case models.KerberosResult:
		return renderKerberos(x)
	case models.MisconfigResult:
		return renderMisconfig(x)
	case models.ADCSResult:
		return renderADCS(x)
	case models.GPOResult:
		return renderGPO(x)
	case models.TrustResult:
		return renderTrusts(x)
	case models.DelegationResult:
		return renderDelegation(x)
	case models.CertResult:
		return renderCerts(x)
	case models.AdminScopeResult:
		return renderAdminScope(x)
	case models.LateralResult:
		return renderLateral(x)
	case models.ShareResult:
		return renderShares(x)
	case models.ACLAuditResult:
		return renderACLs(x)
	case models.TierZeroResult:
		return renderTierZero(x)
	case models.SprawlResult:
		return renderSprawl(x)
	case models.AutoResult:
		var b strings.Builder
		b.WriteString("<h2>Executive Summary</h2>")
		b.WriteString("<div class=\"card\">")
		b.WriteString(fmt.Sprintf("<div><strong>Users:</strong> %d</div>", x.Enum.Users))
		b.WriteString(fmt.Sprintf("<div><strong>Groups:</strong> %d</div>", x.Enum.Groups))
		b.WriteString(fmt.Sprintf("<div><strong>Computers:</strong> %d</div>", x.Enum.Computers))
		b.WriteString("</div>")
		b.WriteString("<h2>Kerberos Exposure Review</h2>")
		b.WriteString(renderKerberos(x.Kerberos))
		b.WriteString("<h2>Misconfiguration Review</h2>")
		b.WriteString(renderMisconfig(x.Misconfig))
		b.WriteString("<h2>AD CS Review</h2>")
		b.WriteString(renderADCS(x.ADCS))
		return b.String()
	default:
		return "<div class=\"card\"><p>No renderer available for module output.</p></div>"
	}
}

func renderKerberos(r models.KerberosResult) string {
	var b strings.Builder
	writeKerbTable := func(title string, items []models.KerberosFinding) {
		b.WriteString("<div class=\"card\">")
		b.WriteString("<h3>" + template.HTMLEscapeString(title) + "</h3>")
		if len(items) == 0 {
			b.WriteString("<p>None found.</p></div>")
			return
		}
		b.WriteString("<table><tr><th>Account</th><th>Reason</th><th>SPNs</th><th>DN</th></tr>")
		for _, f := range items {
			b.WriteString("<tr>")
			b.WriteString("<td>" + template.HTMLEscapeString(f.SAMAccountName) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(f.Reason) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(f.SPNs, ", ")) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(f.DN) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</table></div>")
	}
	writeKerbTable("Accounts with Pre-Authentication Disabled", r.PreAuthDisabled)
	writeKerbTable("Service Accounts with SPNs", r.SPNAccounts)
	writeKerbTable("Privileged Accounts with SPNs", r.PrivilegedSPNAccounts)
	writeKerbTable("Legacy Encryption Review", r.LegacyEncryption)
	writeKerbTable("Password Age Review", r.PasswordAgeReview)
	return b.String()
}

func renderMisconfig(r models.MisconfigResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Findings</h3>")
	if len(r.Findings) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Remediation</th></tr>")
	for _, f := range r.Findings {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(string(f.Severity)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Category) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Title) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Description) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Remediation) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderADCS(r models.ADCSResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Certificate Templates</h3>")
	if len(r.Templates) == 0 {
		b.WriteString("<p>No templates returned in current review scope.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Name</th><th>Flags</th><th>Risk Summary</th></tr>")
	for _, t := range r.Templates {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Name) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(t.Flags, ", ")) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.RiskSummary) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderGPO(r models.GPOResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>GPOs</h3>")
	if len(r.GPOs) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	if len(r.Summary) > 0 {
		b.WriteString(fmt.Sprintf("<p><strong>Total:</strong> %d | <strong>Info:</strong> %d | <strong>Low:</strong> %d | <strong>Medium:</strong> %d | <strong>High:</strong> %d | <strong>Critical:</strong> %d</p>",
			r.Summary["total"], r.Summary["info"], r.Summary["low"], r.Summary["medium"], r.Summary["high"], r.Summary["critical"]))
	}
	b.WriteString("<table><tr><th>Severity</th><th>Name</th><th>GUID</th><th>Path</th><th>Version</th><th>Changed</th><th>Flags</th><th>Notes</th></tr>")
	for _, g := range r.GPOs {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(string(g.Severity)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Name) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.GUID) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Path) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Version) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Changed) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Flags) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Description) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderTrusts(r models.TrustResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Trusts</h3>")
	if len(r.Trusts) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Partner</th><th>Flat Name</th><th>Direction</th><th>Type</th></tr>")
	for _, t := range r.Trusts {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Partner) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.FlatName) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Direction) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Type) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderDelegation(r models.DelegationResult) string {
	var b strings.Builder
	write := func(title string, rows []models.DelegationFinding) {
		b.WriteString("<div class=\"card\"><h3>" + template.HTMLEscapeString(title) + "</h3>")
		if len(rows) == 0 {
			b.WriteString("<p>None found.</p></div>")
			return
		}
		b.WriteString("<table><tr><th>Principal</th><th>Reason</th><th>Targets</th><th>DN</th></tr>")
		for _, row := range rows {
			b.WriteString("<tr>")
			b.WriteString("<td>" + template.HTMLEscapeString(row.Principal) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(row.Reason) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(row.Targets, ", ")) + "</td>")
			b.WriteString("<td>" + template.HTMLEscapeString(row.DN) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</table></div>")
	}
	write("Unconstrained Delegation", r.Unconstrained)
	write("Constrained Delegation", r.Constrained)
	write("Resource-Based Constrained Delegation", r.ResourceBased)
	return b.String()
}

func renderCerts(r models.CertResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Templates</h3>")
	if len(r.Templates) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Name</th><th>Display Name</th><th>EKUs</th><th>Risk Summary</th></tr>")
	for _, t := range r.Templates {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Name) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.DisplayName) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(t.EKUs, ", ")) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.RiskSummary) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderAdminScope(r models.AdminScopeResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Privileged Groups</h3>")
	if len(r.Groups) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Group</th><th>Member Count</th><th>Members</th></tr>")
	for _, g := range r.Groups {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(g.Name) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(fmt.Sprintf("%d", g.MemberCount)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(g.Members, ", ")) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderLateral(r models.LateralResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Remote Management Surface</h3>")
	if len(r.Targets) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Host</th><th>Services</th></tr>")
	for _, t := range r.Targets {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(t.Host) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(t.Services, ", ")) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderShares(r models.ShareResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>SMB Exposure</h3>")
	if len(r.Shares) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Host</th><th>SMB Reachable</th><th>Notes</th></tr>")
	for _, s := range r.Shares {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(s.Host) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(fmt.Sprintf("%t", s.SMBReachable)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(strings.Join(s.Notes, ", ")) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderACLs(r models.ACLAuditResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>ACL Audit Findings</h3>")
	if len(r.Findings) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Severity</th><th>Object</th><th>Type</th><th>Principal</th><th>Right</th><th>Note</th><th>Remediation</th></tr>")
	for _, f := range r.Findings {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(string(f.Severity)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Object) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.ObjectType) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Principal) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Right) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Note) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Remediation) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderTierZero(r models.TierZeroResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Tier 0 Assets</h3>")
	if len(r.Assets) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Category</th><th>Name</th><th>Detail</th></tr>")
	for _, a := range r.Assets {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(a.Category) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(a.Name) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(a.Detail) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderSprawl(r models.SprawlResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Privilege Sprawl Findings</h3>")
	if len(r.Findings) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}
	b.WriteString("<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Description</th><th>Remediation</th></tr>")
	for _, f := range r.Findings {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(string(f.Severity)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Category) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Object) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Description) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Remediation) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}
