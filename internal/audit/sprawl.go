package audit

import (
	"argus/internal/models"
	"strings"
)

func SprawlReview(groups []models.GroupRecord) models.SprawlResult {
	result := models.SprawlResult{
		Findings: make([]models.SprawlFinding, 0),
	}

	memberToGroups := make(map[string][]string)

	privilegedNames := make(map[string]bool)
	for _, g := range groups {
		privilegedNames[strings.ToLower(g.Name)] = true
	}

	for _, g := range groups {
		if len(g.Members) > 10 {
			result.Findings = append(result.Findings, models.SprawlFinding{
				Category:    "Broad Admin Membership",
				Object:      g.Name,
				Severity:    models.SeverityHigh,
				Description: "Privileged group has a broad direct membership footprint.",
				Remediation: "Reduce standing membership and move toward just-in-time or tightly scoped administration.",
			})
		}

		nestedCount := 0
		for _, m := range g.Members {
			memberToGroups[strings.ToLower(m)] = append(memberToGroups[strings.ToLower(m)], g.Name)

			memberLower := strings.ToLower(m)
			if strings.Contains(memberLower, "cn=") && strings.Contains(memberLower, "cn=users") {
				nestedCount++
			}
			for p := range privilegedNames {
				if strings.Contains(memberLower, "cn="+strings.ToLower(p)+",") {
					nestedCount++
					break
				}
			}
		}

		if nestedCount > 0 {
			severity := models.SeverityMedium
			if nestedCount > 3 {
				severity = models.SeverityHigh
			}
			result.Findings = append(result.Findings, models.SprawlFinding{
				Category:    "Nested Privileged Grouping",
				Object:      g.Name,
				Severity:    severity,
				Description: "Privileged group contains nested group membership, increasing review complexity and effective privilege sprawl.",
				Remediation: "Flatten unnecessary nesting and document approved administrative inheritance paths.",
			})
		}
	}

	for member, gs := range memberToGroups {
		if len(gs) > 1 {
			result.Findings = append(result.Findings, models.SprawlFinding{
				Category:    "Redundant Admin Delegation",
				Object:      member,
				Severity:    models.SeverityMedium,
				Description: "Identity appears in multiple privileged groups.",
				Remediation: "Review overlapping privileged memberships and keep only the minimum required group assignments.",
			})
		}
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, models.SprawlFinding{
			Category:    "Privilege Hygiene",
			Object:      "Privileged Groups",
			Severity:    models.SeverityInfo,
			Description: "No direct sprawl conditions were identified in the current review scope.",
			Remediation: "Continue periodic review of nested groups, membership breadth, and redundant administrative assignments.",
		})
	}

	return result
}
