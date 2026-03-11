package audit

import (
	"adreview/internal/models"
	"strings"
)

func GPOEnumReview(gpos []models.GPORecord) models.GPOResult {
	result := models.GPOResult{
		GPOs: make([]models.GPOFinding, 0, len(gpos)),
		Summary: map[string]int{
			"total":    0,
			"info":     0,
			"low":      0,
			"medium":   0,
			"high":     0,
			"critical": 0,
		},
	}

	for _, g := range gpos {
		name := g.DisplayName
		if name == "" {
			name = g.Name
		}

		desc := "Group Policy Object discovered"
		severity := models.SeverityInfo

		if g.FileSysPath == "" {
			desc = "Group Policy Object missing gPCFileSysPath"
			severity = models.SeverityHigh
		} else if !strings.Contains(strings.ToLower(g.FileSysPath), "sysvol") {
			desc = "Group Policy Object path does not appear to reference SYSVOL"
			severity = models.SeverityMedium
		} else if g.Version == "" || g.Version == "0" {
			desc = "Group Policy Object has empty or zero version"
			severity = models.SeverityLow
		}

		result.GPOs = append(result.GPOs, models.GPOFinding{
			Name:        name,
			GUID:        g.Name,
			Path:        g.FileSysPath,
			Version:     g.Version,
			Changed:     g.WhenChanged,
			Flags:       g.Flags,
			Description: desc,
			Severity:    severity,
		})

		result.Summary["total"]++
		switch severity {
		case models.SeverityInfo:
			result.Summary["info"]++
		case models.SeverityLow:
			result.Summary["low"]++
		case models.SeverityMedium:
			result.Summary["medium"]++
		case models.SeverityHigh:
			result.Summary["high"]++
		case models.SeverityCritical:
			result.Summary["critical"]++
		}
	}

	return result
}
