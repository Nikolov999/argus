package report

import (
	"argus/internal/models"
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

//go:embed argus.png
var argusLogoPNG []byte

type htmlView struct {
	GeneratedAt string
	Module      string
	Domain      string
	DC          string
	Content     template.HTML
	LogoDataURI template.URL
}

func WriteHTML(path string, module string, cfg models.Config, data interface{}) error {
	content := buildModuleHTML(module, data)
	logoDataURI := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(argusLogoPNG))

	tpl := `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ARGUS Report</title>
<style>
body{
	font-family:Arial,Helvetica,sans-serif;
	margin:0;
	background:#000;
	color:#fff;
}

.header{
	background:linear-gradient(90deg,#6a00ff,#a855f7);
	height:90;
	position:relative;
	padding:50px 40px;
}

.logo{
	position:absolute;
	left:40px;
	top:50%;
	transform:translateY(-50%);
}

.logo img{
	height:200px;
	width:auto;
	display:block;
}

.footer{
	background:linear-gradient(90deg,#6a00ff,#a855f7);
	padding:12px 40px;
	margin-top:40px;
	text-align:center;
	font-size:12px;
}

.container{
	padding:40px;
}

h1,h2,h3{
	margin-bottom:8px;
	color:#fff;
}

.card{
	border:1px solid #fff;
	border-radius:8px;
	padding:16px;
	margin:14px 0;
	background:#000;
}

table{
	border-collapse:collapse;
	width:100%;
	margin-top:10px;
	background:#000;
}

th,td{
	border:1px solid #fff;
	padding:8px;
	text-align:left;
	vertical-align:top;
	color:#fff;
}

th{
	background:#000;
}
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <img src="{{.LogoDataURI}}" alt="ARGUS logo">
  </div>
</div>

<div class="container">

<div class="card">
  <div><strong>Generated:</strong> {{.GeneratedAt}}</div>
  <div><strong>Module:</strong> {{.Module}}</div>
  <div><strong>Domain:</strong> {{.Domain}}</div>
  <div><strong>Domain Controller:</strong> {{.DC}}</div>
</div>

{{.Content}}

</div>

<div class="footer">
ARGUS Security Report Made by: Bobo, EchoPentest
</div>

</body>
</html>`

	view := htmlView{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Module:      module,
		Domain:      cfg.Domain,
		DC:          cfg.DC,
		Content:     template.HTML(content),
		LogoDataURI: logoDataURI,
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
	case models.ACLExposureResult:
		return renderACLExposure(x)
	case models.TierZeroResult:
		return renderTierZero(x)
	case models.SprawlResult:
		return renderSprawl(x)
	case models.BlastResult:
		return renderBlast(x)
	case models.AdminSDResult:
		return renderAdminSD(x)
	case models.ServiceImpactResult:
		return renderServiceImpact(x)
	case models.DCAttackSurfaceResult:
		return renderDCAttackSurface(x)
	case models.PrivMapResult:
		return renderPrivMap(x)
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

func renderACLExposure(r models.ACLExposureResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>ACL Exposure Findings</h3>")
	if len(r.Findings) == 0 {
		b.WriteString("<p>None found.</p></div>")
		return b.String()
	}

	b.WriteString("<table><tr><th>Severity</th><th>Object</th><th>Type</th><th>Principal</th><th>Right</th><th>Reason</th><th>DN</th><th>Inherited</th></tr>")
	for _, f := range r.Findings {
		b.WriteString("<tr>")
		b.WriteString("<td>" + template.HTMLEscapeString(string(f.Severity)) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Object) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.ObjectType) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Principal) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Right) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.Reason) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(f.DN) + "</td>")
		b.WriteString("<td>" + template.HTMLEscapeString(fmt.Sprintf("%t", f.Inherited)) + "</td>")
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

func renderPrivMap(r models.PrivMapResult) string {
	var b strings.Builder
	b.WriteString("<h2>Privileged Membership Map</h2>")
	b.WriteString("<div class=\"card\">")
	b.WriteString(fmt.Sprintf("<div><strong>Domain:</strong> %s</div>", template.HTMLEscapeString(r.Domain)))
	b.WriteString(fmt.Sprintf("<div><strong>Privileged Groups:</strong> %d</div>", r.TotalPrivGroups))
	b.WriteString(fmt.Sprintf("<div><strong>Privileged Users:</strong> %d</div>", r.TotalUsers))
	b.WriteString(fmt.Sprintf("<div><strong>Nested Groups:</strong> %d</div>", r.TotalNestedGroups))
	b.WriteString(fmt.Sprintf("<div><strong>Service Accounts:</strong> %d</div>", r.TotalServiceAccts))
	b.WriteString(fmt.Sprintf("<div><strong>Review Candidates:</strong> %d</div>", r.TotalReviewUsers))
	b.WriteString(fmt.Sprintf("<div><strong>Admin Name Regex:</strong> %s</div>", template.HTMLEscapeString(r.AdminNameRegexUsed)))
	b.WriteString("</div>")

	if len(r.Groups) == 0 {
		b.WriteString("<div class=\"card\"><p>None found.</p></div>")
		return b.String()
	}

	for _, g := range r.Groups {
		b.WriteString("<div class=\"card\">")
		b.WriteString("<h3>" + template.HTMLEscapeString(g.Name) + "</h3>")
		b.WriteString(fmt.Sprintf("<div><strong>DN:</strong> %s</div>", template.HTMLEscapeString(g.DN)))
		b.WriteString(fmt.Sprintf(
			"<div><strong>Direct Members:</strong> %d | <strong>Nested Groups:</strong> %d | <strong>Users:</strong> %d | <strong>Service Accounts:</strong> %d | <strong>Review Candidates:</strong> %d</div>",
			g.DirectMemberCount, len(g.NestedGroups), len(g.PrivilegedUsers), len(g.ServiceAccounts), len(g.ReviewCandidates),
		))

		if len(g.NestedGroups) > 0 {
			b.WriteString("<h4>Nested Groups</h4><table><tr><th>Name</th><th>Path</th><th>DN</th></tr>")
			for _, ng := range g.NestedGroups {
				b.WriteString("<tr><td>" + template.HTMLEscapeString(ng.Name) + "</td><td>" + template.HTMLEscapeString(ng.Path) + "</td><td>" + template.HTMLEscapeString(ng.DN) + "</td></tr>")
			}
			b.WriteString("</table>")
		}

		writeAccounts := func(title string, items []models.Account) {
			if len(items) == 0 {
				return
			}
			b.WriteString("<h4>" + template.HTMLEscapeString(title) + "</h4><table><tr><th>Name</th><th>UPN</th><th>Enabled</th><th>Path</th><th>DN</th></tr>")
			for _, a := range items {
				b.WriteString("<tr>")
				b.WriteString("<td>" + template.HTMLEscapeString(a.Name) + "</td>")
				b.WriteString("<td>" + template.HTMLEscapeString(a.UPN) + "</td>")
				b.WriteString(fmt.Sprintf("<td>%t</td>", a.Enabled))
				b.WriteString("<td>" + template.HTMLEscapeString(a.Path) + "</td>")
				b.WriteString("<td>" + template.HTMLEscapeString(a.DN) + "</td>")
				b.WriteString("</tr>")
			}
			b.WriteString("</table>")
		}

		writeAccounts("Privileged Users", g.PrivilegedUsers)
		writeAccounts("Service Accounts", g.ServiceAccounts)
		writeAccounts("Review Candidates", g.ReviewCandidates)
		b.WriteString("</div>")
	}

	return b.String()
}

func renderBlast(r models.BlastResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Top Identities by Effective Control Spread</h3>")
	if len(r.TopIdentitySpread) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>Kind</th><th>Groups</th><th>Service Hosts</th><th>Score</th><th>Reason</th></tr>")
		for _, row := range r.TopIdentitySpread {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(row.Kind) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.PrivilegedGroups, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.ServiceHosts, ", ")) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.ControlScore)) + "</td><td>" + template.HTMLEscapeString(row.Reason) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>Top Groups by Privilege Concentration</h3>")
	if len(r.TopGroupConcentration) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>Direct</th><th>Nested</th><th>Users</th><th>Service Accounts</th><th>Score</th><th>Key Paths</th></tr>")
		for _, row := range r.TopGroupConcentration {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.DirectMemberCount)) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.NestedGroupCount)) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.UserCount)) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.ServiceAccountCount)) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.ConcentrationScore)) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.KeyPaths, ", ")) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>Privilege Aggregation Points</h3>")
	if len(r.PrivilegeAggregationTop) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Host</th><th>Role</th><th>Privileged Identities</th><th>Service Accounts</th><th>Score</th><th>Reason</th></tr>")
		for _, row := range r.PrivilegeAggregationTop {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Host) + "</td><td>" + template.HTMLEscapeString(row.Role) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.PrivilegedIdentityRefs, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.ServiceAccounts, ", ")) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%d", row.AggregationScore)) + "</td><td>" + template.HTMLEscapeString(row.Reason) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	return b.String()
}

func renderAdminSD(r models.AdminSDResult) string {
	var b strings.Builder
	write := func(title string, rows []models.AdminSDObject) {
		b.WriteString("<div class=\"card\"><h3>" + template.HTMLEscapeString(title) + "</h3>")
		if len(rows) == 0 {
			b.WriteString("<p>None found.</p></div>")
			return
		}
		b.WriteString("<table><tr><th>Name</th><th>Type</th><th>Currently Privileged</th><th>Reasons</th><th>Inheritance Disabled</th><th>Indicator</th><th>DN</th></tr>")
		for _, row := range rows {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(row.ObjectType) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%t", row.CurrentlyPrivileged)) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.PrivilegeReasons, ", ")) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%t", row.InheritanceDisabled)) + "</td><td>" + template.HTMLEscapeString(row.PersistenceIndicator) + "</td><td>" + template.HTMLEscapeString(row.DN) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	write("Protected Objects", r.ProtectedObjects)
	write("adminCount=1 with No Current Reason", r.NoCurrentReason)
	write("Inheritance Disabled Drift", r.InheritanceDisabledDrift)
	write("Stale Protected Objects", r.StaleProtectedObjects)
	write("Persistent ACL Review Objects", r.PersistentACLReviewObjects)
	return b.String()
}

func renderServiceImpact(r models.ServiceImpactResult) string {
	var b strings.Builder
	write := func(title string, rows []models.ServiceImpactAccount) {
		b.WriteString("<div class=\"card\"><h3>" + template.HTMLEscapeString(title) + "</h3>")
		if len(rows) == 0 {
			b.WriteString("<p>None found.</p></div>")
			return
		}
		b.WriteString("<table><tr><th>Name</th><th>Kind</th><th>Privileged</th><th>Reasons</th><th>Hosts</th><th>SPNs</th><th>Impact</th></tr>")
		for _, row := range rows {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(row.Kind) + "</td><td>" + template.HTMLEscapeString(fmt.Sprintf("%t", row.Privileged)) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.PrivilegeReasons, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.Hosts, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.SPNs, ", ")) + "</td><td>" + template.HTMLEscapeString(row.SingleCompromiseImpact) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	write("All Service Accounts", r.Accounts)
	write("Privileged SPN Accounts", r.PrivilegedSPNAccounts)
	write("Broad Reuse Accounts", r.BroadReuseAccounts)
	write("Admin and Service Overlap", r.AdminServiceOverlapAccounts)
	return b.String()
}

func renderDCAttackSurface(r models.DCAttackSurfaceResult) string {
	var b strings.Builder
	b.WriteString("<div class=\"card\"><h3>Who Can Log On to Domain Controllers</h3>")
	if len(r.WhoCanLogOnToDCs) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>Groups</th><th>DN</th></tr>")
		for _, row := range r.WhoCanLogOnToDCs {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.Groups, ", ")) + "</td><td>" + template.HTMLEscapeString(row.DN) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>Nonstandard Accounts Present on Domain Controllers</h3>")
	if len(r.NonstandardAccountsOnDCs) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>Hosts</th><th>SPNs</th><th>Comment</th><th>DN</th></tr>")
		for _, row := range r.NonstandardAccountsOnDCs {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.Hosts, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.SPNs, ", ")) + "</td><td>" + template.HTMLEscapeString(row.Comment) + "</td><td>" + template.HTMLEscapeString(row.DN) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>Protocol Exposure</h3>")
	if len(r.ProtocolExposure) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Host</th><th>Protocols</th><th>Delegation Signals</th><th>DN</th></tr>")
		for _, row := range r.ProtocolExposure {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Host) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.Protocols, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.DelegationSignals, ", ")) + "</td><td>" + template.HTMLEscapeString(row.DN) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>GPOs Affecting the Domain Controllers OU</h3>")
	if len(r.GPOsAffectingDCOU) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Name</th><th>GUID</th><th>Path</th><th>Comment</th></tr>")
		for _, row := range r.GPOsAffectingDCOU {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Name) + "</td><td>" + template.HTMLEscapeString(row.GUID) + "</td><td>" + template.HTMLEscapeString(row.Path) + "</td><td>" + template.HTMLEscapeString(row.Comment) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("<div class=\"card\"><h3>Delegation and Local Group Anomalies</h3>")
	if len(r.DelegationAndGroupAnomaly) == 0 {
		b.WriteString("<p>None found.</p></div>")
	} else {
		b.WriteString("<table><tr><th>Host</th><th>Protocols</th><th>Signals</th><th>DN</th></tr>")
		for _, row := range r.DelegationAndGroupAnomaly {
			b.WriteString("<tr><td>" + template.HTMLEscapeString(row.Host) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.Protocols, ", ")) + "</td><td>" + template.HTMLEscapeString(strings.Join(row.DelegationSignals, ", ")) + "</td><td>" + template.HTMLEscapeString(row.DN) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	if len(r.CollectionNotes) > 0 {
		b.WriteString("<div class=\"card\"><h3>Collection Notes</h3><ul>")
		for _, note := range r.CollectionNotes {
			b.WriteString("<li>" + template.HTMLEscapeString(note) + "</li>")
		}
		b.WriteString("</ul></div>")
	}
	return b.String()
}
