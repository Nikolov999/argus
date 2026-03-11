package audit

import "adreview/internal/models"

func AdminScope(groups []models.GroupRecord) models.AdminScopeResult {
	result := models.AdminScopeResult{
		Groups: make([]models.AdminGroup, 0, len(groups)),
	}

	for _, g := range groups {
		result.Groups = append(result.Groups, models.AdminGroup{
			Name:        g.Name,
			MemberCount: len(g.Members),
			Members:     g.Members,
		})
	}

	return result
}
