package audit

import (
	"adreview/internal/models"
	"strings"
)

func TierZeroInventory(
	cfg models.Config,
	computers []models.ComputerRecord,
	groups []models.GroupRecord,
	users []models.UserRecord,
	enrollmentServices []models.EnrollmentServiceRecord,
) models.TierZeroResult {
	result := models.TierZeroResult{
		Assets: make([]models.TierZeroAsset, 0),
	}

	for _, c := range computers {
		host := firstNonEmpty(c.DNSHostName, c.Name)
		if host == "" {
			continue
		}

		if strings.Contains(strings.ToLower(c.DN), "ou=domain controllers") {
			result.Assets = append(result.Assets, models.TierZeroAsset{
				Category: "Domain Controller",
				Name:     host,
				Detail:   c.OS,
			})
			continue
		}

		nameLower := strings.ToLower(c.Name)
		hostLower := strings.ToLower(c.DNSHostName)
		if strings.Contains(nameLower, "admin") || strings.Contains(nameLower, "paw") || strings.Contains(hostLower, "admin") || strings.Contains(hostLower, "paw") {
			result.Assets = append(result.Assets, models.TierZeroAsset{
				Category: "Admin Workstation Candidate",
				Name:     host,
				Detail:   c.OS,
			})
		}
	}

	for _, g := range groups {
		result.Assets = append(result.Assets, models.TierZeroAsset{
			Category: "Privileged Group",
			Name:     g.Name,
			Detail:   strings.Join(g.Members, ", "),
		})
	}

	for _, u := range users {
		if isPrivilegedUser(u) {
			result.Assets = append(result.Assets, models.TierZeroAsset{
				Category: "Privileged User",
				Name:     u.SAMAccountName,
				Detail:   u.DistinguishedName,
			})
		}

		if len(u.ServicePrincipalName) > 0 && (isPrivilegedUser(u) || u.AdminCount == 1) {
			result.Assets = append(result.Assets, models.TierZeroAsset{
				Category: "Critical Service Account",
				Name:     u.SAMAccountName,
				Detail:   strings.Join(u.ServicePrincipalName, ", "),
			})
		}
	}

	for _, e := range enrollmentServices {
		name := firstNonEmpty(e.DNSHostName, e.Name)
		result.Assets = append(result.Assets, models.TierZeroAsset{
			Category: "PKI Server",
			Name:     name,
			Detail:   e.Name,
		})
	}

	return result
}

func isPrivilegedUser(u models.UserRecord) bool {
	if u.AdminCount == 1 {
		return true
	}
	for _, g := range u.MemberOf {
		x := strings.ToLower(g)
		if strings.Contains(x, "domain admins") ||
			strings.Contains(x, "enterprise admins") ||
			strings.Contains(x, "administrators") ||
			strings.Contains(x, "account operators") ||
			strings.Contains(x, "server operators") ||
			strings.Contains(x, "backup operators") {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
