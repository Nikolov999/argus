package audit

import "adreview/internal/models"

func TrustAudit(trusts []models.TrustRecord) models.TrustResult {
	result := models.TrustResult{
		Trusts: make([]models.TrustFinding, 0, len(trusts)),
	}

	for _, t := range trusts {
		result.Trusts = append(result.Trusts, models.TrustFinding{
			Partner:   t.Partner,
			FlatName:  t.FlatName,
			Direction: trustDirection(t.Direction),
			Type:      trustType(t.Type),
		})
	}

	return result
}

func trustDirection(v int) string {
	switch v {
	case 0:
		return "Disabled"
	case 1:
		return "Inbound"
	case 2:
		return "Outbound"
	case 3:
		return "Bidirectional"
	default:
		return "Unknown"
	}
}

func trustType(v int) string {
	switch v {
	case 1:
		return "Windows AD"
	case 2:
		return "Windows non-AD"
	case 3:
		return "MIT Kerberos"
	case 4:
		return "DCE"
	default:
		return "Unknown"
	}
}
