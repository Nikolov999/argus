package audit

import (
	"adreview/internal/models"
	"strings"
)

func CertSurface(templates []models.CertTemplate) models.CertResult {
	result := models.CertResult{
		Templates: make([]models.CertFinding, 0, len(templates)),
	}

	for _, t := range templates {
		risk := "Review enrollment scope, EKUs, and subject name policy."
		ekus := strings.ToLower(strings.Join(t.EKUs, " "))

		switch {
		case strings.Contains(ekus, "1.3.6.1.5.5.7.3.2"):
			risk = "Client Authentication EKU present."
		case strings.Contains(ekus, "2.5.29.37.0"):
			risk = "Any Purpose EKU present."
		case strings.Contains(ekus, "1.3.6.1.4.1.311.20.2.2"):
			risk = "Smart Card Logon EKU present."
		}

		result.Templates = append(result.Templates, models.CertFinding{
			Name:        t.Name,
			DisplayName: t.DisplayName,
			EKUs:        t.EKUs,
			RiskSummary: risk,
		})
	}

	return result
}
