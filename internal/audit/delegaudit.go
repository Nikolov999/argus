package audit

import "argus/internal/models"

const (
	uacTrustedForDelegation = 0x00080000
)

func DelegAudit(principals []models.DelegationPrincipal) models.DelegationResult {
	result := models.DelegationResult{}

	for _, p := range principals {
		if p.SAMAccountName == "" {
			continue
		}

		if p.UAC&uacTrustedForDelegation != 0 {
			result.Unconstrained = append(result.Unconstrained, models.DelegationFinding{
				Principal: p.SAMAccountName,
				DN:        p.DN,
				Reason:    "Unconstrained delegation enabled",
			})
		}

		if len(p.AllowedToDelegateTo) > 0 {
			result.Constrained = append(result.Constrained, models.DelegationFinding{
				Principal: p.SAMAccountName,
				DN:        p.DN,
				Reason:    "Constrained delegation configured",
				Targets:   p.AllowedToDelegateTo,
			})
		}

		if p.HasRBCDDescriptor {
			result.ResourceBased = append(result.ResourceBased, models.DelegationFinding{
				Principal: p.SAMAccountName,
				DN:        p.DN,
				Reason:    "Resource-based constrained delegation descriptor present",
			})
		}
	}

	return result
}
