package audit

import "argus/internal/models"

func ADCSReview() models.ADCSResult {
	return models.ADCSResult{
		Templates: []models.ADCSTemplate{
			{
				Name:        "User",
				Flags:       []string{"Client Authentication"},
				RiskSummary: "Baseline built-in template. Review enrollment scope and EKUs.",
			},
			{
				Name:        "Machine",
				Flags:       []string{"Client Authentication", "Server Authentication"},
				RiskSummary: "Common machine template. Review enrollment permissions and auto-enrollment scope.",
			},
		},
	}
}
