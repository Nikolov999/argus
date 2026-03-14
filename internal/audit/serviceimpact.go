package audit

import (
	"fmt"
	"sort"
	"strings"

	ldapclient "argus/internal/ldap"
	"argus/internal/models"
)

func ServiceImpactReview(client *ldapclient.Client, cfg models.Config) (models.ServiceImpactResult, error) {
	entries, err := client.SearchServiceAccountEntries()
	if err != nil {
		return models.ServiceImpactResult{}, err
	}
	reasons, err := privilegedReasonMap(client, cfg)
	if err != nil {
		return models.ServiceImpactResult{}, err
	}

	result := models.ServiceImpactResult{}
	for _, e := range entries {
		spns := uniqueStrings(e.GetAttributeValues("servicePrincipalName"))
		if len(spns) == 0 {
			continue
		}
		hosts := hostsFromSPNs(spns)
		dn := e.GetAttributeValue("distinguishedName")
		row := models.ServiceImpactAccount{
			Name:                   pickName(e),
			DN:                     dn,
			Kind:                   serviceKind(e),
			Privileged:             len(reasons[strings.ToLower(dn)]) > 0,
			PrivilegeReasons:       uniqueStrings(reasons[strings.ToLower(dn)]),
			HostCount:              len(hosts),
			Hosts:                  hosts,
			SPNs:                   spns,
			SingleCompromiseImpact: fmt.Sprintf("single account compromise would affect %d named systems from SPN data", len(hosts)),
		}
		result.Accounts = append(result.Accounts, row)
		if row.Privileged {
			result.PrivilegedSPNAccounts = append(result.PrivilegedSPNAccounts, row)
			result.AdminServiceOverlapAccounts = append(result.AdminServiceOverlapAccounts, row)
		}
		if row.HostCount >= 3 {
			result.BroadReuseAccounts = append(result.BroadReuseAccounts, row)
		}
	}

	sortServiceAccounts(result.Accounts)
	sortServiceAccounts(result.PrivilegedSPNAccounts)
	sortServiceAccounts(result.BroadReuseAccounts)
	sortServiceAccounts(result.AdminServiceOverlapAccounts)

	return result, nil
}

func sortServiceAccounts(rows []models.ServiceImpactAccount) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].HostCount != rows[j].HostCount {
			return rows[i].HostCount > rows[j].HostCount
		}
		if rows[i].Privileged != rows[j].Privileged {
			return rows[i].Privileged
		}
		return rows[i].Name < rows[j].Name
	})
}

func serviceKind(e interface{ GetAttributeValues(string) []string }) string {
	classes := e.GetAttributeValues("objectClass")
	for _, v := range classes {
		if strings.EqualFold(v, "msDS-GroupManagedServiceAccount") || strings.EqualFold(v, "msDS-ManagedServiceAccount") {
			return "managed-service-account"
		}
	}
	return "service-account"
}
