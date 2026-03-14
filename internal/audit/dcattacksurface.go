package audit

import (
	"fmt"
	"sort"
	"strings"

	ldapclient "argus/internal/ldap"
	"argus/internal/models"
)

func DCAttackSurfaceReview(client *ldapclient.Client, cfg models.Config) (models.DCAttackSurfaceResult, error) {
	priv, err := PrivMapReview(client, cfg)
	if err != nil {
		return models.DCAttackSurfaceResult{}, err
	}
	dcs, err := client.SearchDCComputerEntries()
	if err != nil {
		return models.DCAttackSurfaceResult{}, err
	}
	services, err := client.SearchServiceAccountEntries()
	if err != nil {
		return models.DCAttackSurfaceResult{}, err
	}
	dcOU, err := client.GetEntryByDN("OU=Domain Controllers,"+cfg.BaseDN, []string{"distinguishedName", "gPLink", "gPOptions"})
	if err != nil {
		dcOU = nil
	}
	gpoMap, err := client.SearchGPOMap()
	if err != nil {
		return models.DCAttackSurfaceResult{}, err
	}

	result := models.DCAttackSurfaceResult{
		CollectionNotes: []string{
			"Protocol exposure is inferred from directory-advertised SPNs and host roles. No network probing is performed.",
			"Recent privileged authentications to DCs require event log telemetry and are outside the current read-only LDAP collection scope.",
		},
	}

	who := map[string]*models.DCAttackSurfaceIdentity{}
	allowedGroups := map[string]struct{}{
		"Domain Admins":     {},
		"Enterprise Admins": {},
		"Administrators":    {},
		"Account Operators": {},
		"Server Operators":  {},
		"Backup Operators":  {},
		"Print Operators":   {},
	}
	for _, g := range priv.Groups {
		if _, ok := allowedGroups[g.Name]; !ok {
			continue
		}
		for _, u := range g.PrivilegedUsers {
			row := who[strings.ToLower(u.DN)]
			if row == nil {
				row = &models.DCAttackSurfaceIdentity{Name: u.Name, DN: u.DN}
				who[strings.ToLower(u.DN)] = row
			}
			row.Groups = appendIfMissing(row.Groups, g.Name)
		}
		for _, u := range g.ServiceAccounts {
			row := who[strings.ToLower(u.DN)]
			if row == nil {
				row = &models.DCAttackSurfaceIdentity{Name: u.Name, DN: u.DN}
				who[strings.ToLower(u.DN)] = row
			}
			row.Groups = appendIfMissing(row.Groups, g.Name)
		}
	}
	for _, row := range who {
		sort.Strings(row.Groups)
		result.WhoCanLogOnToDCs = append(result.WhoCanLogOnToDCs, *row)
	}
	sort.Slice(result.WhoCanLogOnToDCs, func(i, j int) bool {
		if len(result.WhoCanLogOnToDCs[i].Groups) != len(result.WhoCanLogOnToDCs[j].Groups) {
			return len(result.WhoCanLogOnToDCs[i].Groups) > len(result.WhoCanLogOnToDCs[j].Groups)
		}
		return result.WhoCanLogOnToDCs[i].Name < result.WhoCanLogOnToDCs[j].Name
	})

	dcHostSet := map[string]struct{}{}
	for _, dc := range dcs {
		dcHostSet[normalizeHost(chooseFirst(dc.GetAttributeValue("dNSHostName"), dc.GetAttributeValue("name")))] = struct{}{}
		result.ProtocolExposure = append(result.ProtocolExposure, models.DCAttackSurfaceHost{
			Host:              chooseFirst(dc.GetAttributeValue("dNSHostName"), dc.GetAttributeValue("name")),
			DN:                dc.GetAttributeValue("distinguishedName"),
			Protocols:         inferManagementProtocols(dc.GetAttributeValues("servicePrincipalName")),
			DelegationSignals: delegationSignals(dc),
		})
	}
	sort.Slice(result.ProtocolExposure, func(i, j int) bool { return result.ProtocolExposure[i].Host < result.ProtocolExposure[j].Host })

	for _, svc := range services {
		hosts := hostsFromSPNs(svc.GetAttributeValues("servicePrincipalName"))
		matched := make([]string, 0)
		for _, h := range hosts {
			if _, ok := dcHostSet[normalizeHost(h)]; ok {
				matched = appendIfMissing(matched, h)
			}
		}
		if len(matched) == 0 {
			continue
		}
		comment := "SPN-bearing account references a domain controller"
		if !strings.HasSuffix(strings.ToLower(svc.GetAttributeValue("sAMAccountName")), "$") {
			comment = "non-computer account references a domain controller via SPN"
		}
		result.NonstandardAccountsOnDCs = append(result.NonstandardAccountsOnDCs, models.DCAttackSurfaceAccount{
			Name:    pickName(svc),
			DN:      svc.GetAttributeValue("distinguishedName"),
			Hosts:   matched,
			SPNs:    uniqueStrings(svc.GetAttributeValues("servicePrincipalName")),
			Comment: comment,
		})
	}
	sort.Slice(result.NonstandardAccountsOnDCs, func(i, j int) bool {
		if len(result.NonstandardAccountsOnDCs[i].Hosts) != len(result.NonstandardAccountsOnDCs[j].Hosts) {
			return len(result.NonstandardAccountsOnDCs[i].Hosts) > len(result.NonstandardAccountsOnDCs[j].Hosts)
		}
		return result.NonstandardAccountsOnDCs[i].Name < result.NonstandardAccountsOnDCs[j].Name
	})

	for _, row := range result.ProtocolExposure {
		if len(row.DelegationSignals) > 0 || len(row.Protocols) > 2 {
			result.DelegationAndGroupAnomaly = append(result.DelegationAndGroupAnomaly, row)
		}
	}

	if dcOU != nil {
		for _, link := range parseGPLinks(dcOU.GetAttributeValue("gPLink")) {
			if gpo, ok := gpoMap[strings.ToLower(link)]; ok {
				result.GPOsAffectingDCOU = append(result.GPOsAffectingDCOU, models.DCAttackSurfaceGPO{
					Name:    chooseFirst(gpo.DisplayName, gpo.Name),
					GUID:    gpo.Name,
					Path:    gpo.FileSysPath,
					Comment: "Linked to Domain Controllers OU",
				})
			} else {
				result.GPOsAffectingDCOU = append(result.GPOsAffectingDCOU, models.DCAttackSurfaceGPO{
					Name:    link,
					Comment: "Linked to Domain Controllers OU",
				})
			}
		}
	}

	return result, nil
}

func inferManagementProtocols(spns []string) []string {
	out := make([]string, 0)
	for _, spn := range spns {
		service := strings.ToUpper(strings.TrimSpace(strings.SplitN(spn, "/", 2)[0]))
		switch service {
		case "TERMSRV":
			out = appendIfMissing(out, "RDP")
		case "WSMAN", "HTTP":
			out = appendIfMissing(out, "WinRM/HTTP")
		case "CIFS":
			out = appendIfMissing(out, "SMB")
		case "HOST", "LDAP", "GC", "RPC":
			out = appendIfMissing(out, service)
		}
	}
	sort.Strings(out)
	return out
}

func delegationSignals(e interface{ GetAttributeValue(string) string }) []string {
	out := make([]string, 0)
	uac := strings.TrimSpace(e.GetAttributeValue("userAccountControl"))
	if uac != "" {
		out = append(out, fmt.Sprintf("userAccountControl=%s", uac))
	}
	return out
}

func parseGPLinks(raw string) []string {
	parts := strings.Split(raw, "[")
	out := make([]string, 0)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if idx := strings.Index(p, ";"); idx > 0 {
			link := strings.TrimSpace(p[:idx])
			link = strings.TrimPrefix(link, "LDAP://")
			link = strings.TrimPrefix(link, "ldap://")
			if link != "" {
				out = append(out, link)
			}
		}
	}
	return uniqueStrings(out)
}
