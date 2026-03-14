package audit

import (
	"encoding/binary"
	"sort"
	"strings"

	ldapclient "argus/internal/ldap"
	"argus/internal/models"
)

func AdminSDReview(client *ldapclient.Client, cfg models.Config) (models.AdminSDResult, error) {
	objects, err := client.SearchAdminSDHolderEntries()
	if err != nil {
		return models.AdminSDResult{}, err
	}
	privReasons, err := privilegedReasonMap(client, cfg)
	if err != nil {
		return models.AdminSDResult{}, err
	}

	result := models.AdminSDResult{}
	for _, e := range objects {
		name := pickName(e)
		dn := e.GetAttributeValue("distinguishedName")
		kind := adminSDObjectType(e)
		reasons := uniqueStrings(privReasons[strings.ToLower(dn)])
		protected := sdDACLProtected(e.GetRawAttributeValue("nTSecurityDescriptor"))

		persistence := "Protected by current privilege"
		if len(reasons) == 0 && protected {
			persistence = "adminCount=1 with protected DACL and no current protected-group path"
		} else if len(reasons) == 0 {
			persistence = "adminCount=1 with no current protected-group path"
		} else if protected {
			persistence = "current protected object with inheritance disabled"
		}

		row := models.AdminSDObject{
			Name:                 name,
			ObjectType:           kind,
			DN:                   dn,
			AdminCount:           1,
			CurrentlyPrivileged:  len(reasons) > 0,
			PrivilegeReasons:     reasons,
			InheritanceDisabled:  protected,
			PersistenceIndicator: persistence,
		}

		result.ProtectedObjects = append(result.ProtectedObjects, row)
		if len(reasons) == 0 {
			result.NoCurrentReason = append(result.NoCurrentReason, row)
			result.StaleProtectedObjects = append(result.StaleProtectedObjects, row)
		}
		if protected && (len(reasons) == 0 || kind == "group") {
			result.InheritanceDisabledDrift = append(result.InheritanceDisabledDrift, row)
		}
		if protected && len(reasons) == 0 {
			result.PersistentACLReviewObjects = append(result.PersistentACLReviewObjects, row)
		}
	}

	sortAdminSD := func(rows []models.AdminSDObject) {
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].InheritanceDisabled != rows[j].InheritanceDisabled {
				return rows[i].InheritanceDisabled
			}
			return rows[i].Name < rows[j].Name
		})
	}
	result.ProtectedObjects = sortAdminRows(result.ProtectedObjects, sortAdminSD)
	result.NoCurrentReason = sortAdminRows(result.NoCurrentReason, sortAdminSD)
	result.InheritanceDisabledDrift = sortAdminRows(result.InheritanceDisabledDrift, sortAdminSD)
	result.StaleProtectedObjects = sortAdminRows(result.StaleProtectedObjects, sortAdminSD)
	result.PersistentACLReviewObjects = sortAdminRows(result.PersistentACLReviewObjects, sortAdminSD)

	return result, nil
}

func privilegedReasonMap(client *ldapclient.Client, cfg models.Config) (map[string][]string, error) {
	priv, err := PrivMapReview(client, cfg)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, g := range priv.Groups {
		for _, u := range g.PrivilegedUsers {
			out[strings.ToLower(u.DN)] = appendIfMissing(out[strings.ToLower(u.DN)], g.Name)
		}
		for _, u := range g.ServiceAccounts {
			out[strings.ToLower(u.DN)] = appendIfMissing(out[strings.ToLower(u.DN)], g.Name)
		}
		out[strings.ToLower(g.DN)] = appendIfMissing(out[strings.ToLower(g.DN)], g.Name)
		for _, ng := range g.NestedGroups {
			out[strings.ToLower(ng.DN)] = appendIfMissing(out[strings.ToLower(ng.DN)], g.Name)
		}
	}
	return out, nil
}

func sdDACLProtected(sd []byte) bool {
	if len(sd) < 4 {
		return false
	}
	control := binary.LittleEndian.Uint16(sd[2:4])
	return (control & 0x1000) != 0
}

func adminSDObjectType(e interface{ GetAttributeValues(string) []string }) string {
	classes := e.GetAttributeValues("objectClass")
	for i := len(classes) - 1; i >= 0; i-- {
		v := strings.ToLower(strings.TrimSpace(classes[i]))
		switch v {
		case "user", "group", "computer", "organizationalunit", "msds-groupmanagedserviceaccount", "msds-managedserviceaccount":
			return v
		}
	}
	return "object"
}

func sortAdminRows(rows []models.AdminSDObject, sorter func([]models.AdminSDObject)) []models.AdminSDObject {
	if len(rows) == 0 {
		return rows
	}
	sorter(rows)
	return rows
}
