package audit

import "argus/internal/models"

func ACLAudit(targets []models.ACLTargetRecord) models.ACLAuditResult {
	result := models.ACLAuditResult{
		Findings: make([]models.ACLFinding, 0),
	}

	for _, t := range targets {
		if t.Name == "" {
			continue
		}

		if t.ManagedBy != "" {
			severity := models.SeverityMedium
			note := "Object has a managedBy owner/delegation indicator and should have its effective permissions reviewed."
			right := "Delegation Indicator (managedBy)"
			remediation := "Validate that the delegated manager is approved, documented, and not over-privileged."

			if t.ObjectType == "group" || t.ObjectType == "gpo" || t.ObjectType == "ou" {
				severity = models.SeverityHigh
				note = "High-value container or policy object has a managedBy delegation indicator."
				remediation = "Review delegated administration and confirm only approved identities can manage this object."
			}

			result.Findings = append(result.Findings, models.ACLFinding{
				Object:      t.Name,
				ObjectType:  t.ObjectType,
				Principal:   t.ManagedBy,
				Right:       right,
				Severity:    severity,
				Remediation: remediation,
				Note:        note,
			})
		}

		if t.AdminCount == 1 {
			result.Findings = append(result.Findings, models.ACLFinding{
				Object:      t.Name,
				ObjectType:  t.ObjectType,
				Principal:   "PROTECTED OBJECT",
				Right:       "AdminSDHolder-protected",
				Severity:    models.SeverityInfo,
				Remediation: "Review this protected object for unintended delegated control and verify explicit permissions are still required.",
				Note:        "Object is protected by privileged-object handling and should receive regular DACL review.",
			})
		}
	}

	return result
}
