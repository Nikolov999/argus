package audit

import "argus/internal/models"

func MisconfigReview(users []models.UserRecord) models.MisconfigResult {
	findings := make([]models.MisconfigFinding, 0)

	for _, u := range users {
		if len(u.ServicePrincipalName) > 0 && isPrivileged(u) {
			findings = append(findings, models.MisconfigFinding{
				Severity:    models.SeverityHigh,
				Category:    "Kerberos",
				Title:       "Privileged account with SPNs",
				Description: "A privileged account has service principal names registered. This expands attack surface and should be reviewed.",
				Remediation: "Move service roles to dedicated least-privileged service accounts and remove unnecessary SPNs.",
			})
			break
		}
	}

	for _, u := range users {
		if hasUACFlag(u.UserAccountControl, uacDontRequirePreauth) {
			findings = append(findings, models.MisconfigFinding{
				Severity:    models.SeverityHigh,
				Category:    "Kerberos",
				Title:       "Account with pre-authentication disabled",
				Description: "One or more accounts have Kerberos pre-authentication disabled.",
				Remediation: "Re-enable pre-authentication unless a documented exception exists and is still required.",
			})
			break
		}
	}

	for _, u := range users {
		if usesLegacyEncryption(u.MSEncryptionTypes) {
			findings = append(findings, models.MisconfigFinding{
				Severity:    models.SeverityMedium,
				Category:    "Kerberos",
				Title:       "Legacy Kerberos encryption settings detected",
				Description: "One or more accounts do not appear to require AES-capable encryption settings.",
				Remediation: "Standardize on AES-capable Kerberos settings and validate application compatibility before rollout.",
			})
			break
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.MisconfigFinding{
			Severity:    models.SeverityInfo,
			Category:    "General",
			Title:       "No high-confidence issues found in current review scope",
			Description: "The current read-only checks did not identify issues within the enabled modules.",
			Remediation: "Continue with periodic review and expand controls for AD CS, ACLs, delegation, GPO permissions, and trust posture.",
		})
	}

	return models.MisconfigResult{Findings: findings}
}
