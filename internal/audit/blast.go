package audit

import (
	"fmt"
	"sort"
	"strings"

	ldapclient "argus/internal/ldap"
	"argus/internal/models"
)

func BlastReview(client *ldapclient.Client, cfg models.Config) (models.BlastResult, error) {
	priv, err := PrivMapReview(client, cfg)
	if err != nil {
		return models.BlastResult{}, err
	}

	computers, err := client.SearchComputers()
	if err != nil {
		return models.BlastResult{}, err
	}

	serviceEntries, err := client.SearchServiceAccountEntries()
	if err != nil {
		return models.BlastResult{}, err
	}

	identityMap := map[string]*models.BlastIdentitySummary{}
	for _, g := range priv.Groups {
		for _, u := range g.PrivilegedUsers {
			key := strings.ToLower(u.DN)
			row := identityMap[key]
			if row == nil {
				row = &models.BlastIdentitySummary{Name: u.Name, Kind: "user", DN: u.DN}
				identityMap[key] = row
			}
			row.PrivilegedGroups = appendIfMissing(row.PrivilegedGroups, g.Name)
		}
		for _, u := range g.ServiceAccounts {
			key := strings.ToLower(u.DN)
			row := identityMap[key]
			if row == nil {
				row = &models.BlastIdentitySummary{Name: u.Name, Kind: "service", DN: u.DN}
				identityMap[key] = row
			}
			row.PrivilegedGroups = appendIfMissing(row.PrivilegedGroups, g.Name)
		}
	}

	hostServices := map[string][]string{}
	for _, e := range serviceEntries {
		name := pickName(e)
		dn := e.GetAttributeValue("distinguishedName")
		kind := "service"
		if !isServiceAccount(e) {
			kind = "user"
		}
		key := strings.ToLower(dn)
		row := identityMap[key]
		if row == nil {
			row = &models.BlastIdentitySummary{Name: name, Kind: kind, DN: dn}
			identityMap[key] = row
		}
		for _, host := range hostsFromSPNs(e.GetAttributeValues("servicePrincipalName")) {
			row.ServiceHosts = appendIfMissing(row.ServiceHosts, host)
			hostServices[host] = appendIfMissing(hostServices[host], name)
		}
	}

	identities := make([]models.BlastIdentitySummary, 0, len(identityMap))
	for _, row := range identityMap {
		row.PrivilegedGroupCount = len(row.PrivilegedGroups)
		row.ServiceHostCount = len(row.ServiceHosts)
		row.ControlScore = (row.PrivilegedGroupCount * 5) + row.ServiceHostCount
		switch {
		case row.PrivilegedGroupCount > 0 && row.ServiceHostCount > 0:
			row.Reason = fmt.Sprintf("member of %d privileged groups and linked to %d service hosts", row.PrivilegedGroupCount, row.ServiceHostCount)
		case row.PrivilegedGroupCount > 0:
			row.Reason = fmt.Sprintf("member of %d privileged groups", row.PrivilegedGroupCount)
		case row.ServiceHostCount > 0:
			row.Reason = fmt.Sprintf("service identity reused across %d hosts", row.ServiceHostCount)
		default:
			row.Reason = "review candidate"
		}
		sort.Strings(row.PrivilegedGroups)
		sort.Strings(row.ServiceHosts)
		identities = append(identities, *row)
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].ControlScore != identities[j].ControlScore {
			return identities[i].ControlScore > identities[j].ControlScore
		}
		return identities[i].Name < identities[j].Name
	})
	if len(identities) > 10 {
		identities = identities[:10]
	}

	groups := make([]models.BlastGroupSummary, 0, len(priv.Groups))
	for _, g := range priv.Groups {
		groups = append(groups, models.BlastGroupSummary{
			Name:                g.Name,
			DN:                  g.DN,
			DirectMemberCount:   g.DirectMemberCount,
			NestedGroupCount:    len(g.NestedGroups),
			UserCount:           len(g.PrivilegedUsers),
			ServiceAccountCount: len(g.ServiceAccounts),
			ConcentrationScore:  (g.DirectMemberCount * 2) + (len(g.NestedGroups) * 3) + (len(g.ServiceAccounts) * 2),
			KeyPaths:            topPaths(g),
		})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].ConcentrationScore != groups[j].ConcentrationScore {
			return groups[i].ConcentrationScore > groups[j].ConcentrationScore
		}
		return groups[i].Name < groups[j].Name
	})
	if len(groups) > 10 {
		groups = groups[:10]
	}

	hosts := make([]models.BlastHostSummary, 0, len(computers))
	for _, c := range computers {
		hostKey := normalizeHost(chooseFirst(c.DNSHostName, c.Name))
		serviceAccounts := uniqueStrings(hostServices[hostKey])
		refs := make([]string, 0)
		for _, id := range identities {
			for _, h := range id.ServiceHosts {
				if normalizeHost(h) == hostKey {
					refs = appendIfMissing(refs, id.Name)
				}
			}
		}

		role := "Member Server"
		reason := "service and privileged identity aggregation"
		score := len(serviceAccounts) + len(refs)
		if isDCHost(c.DN, c.Name) {
			role = "Domain Controller"
			reason = "tier 0 host and authentication boundary"
			score += 10
		}
		if score == 0 && role != "Domain Controller" {
			continue
		}
		hosts = append(hosts, models.BlastHostSummary{
			Host:                   chooseFirst(c.DNSHostName, c.Name),
			DN:                     c.DN,
			Role:                   role,
			PrivilegedIdentityRefs: uniqueStrings(refs),
			ServiceAccounts:        serviceAccounts,
			AggregationScore:       score,
			Reason:                 reason,
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].AggregationScore != hosts[j].AggregationScore {
			return hosts[i].AggregationScore > hosts[j].AggregationScore
		}
		return hosts[i].Host < hosts[j].Host
	})
	if len(hosts) > 10 {
		hosts = hosts[:10]
	}

	return models.BlastResult{
		TopIdentitySpread:       identities,
		TopGroupConcentration:   groups,
		PrivilegeAggregationTop: hosts,
	}, nil
}

func topPaths(g models.PrivilegedGroup) []string {
	out := make([]string, 0, 3)
	for _, ng := range g.NestedGroups {
		out = appendIfMissing(out, ng.Path)
		if len(out) == 3 {
			return out
		}
	}
	for _, u := range g.ServiceAccounts {
		out = appendIfMissing(out, u.Path)
		if len(out) == 3 {
			return out
		}
	}
	for _, u := range g.PrivilegedUsers {
		out = appendIfMissing(out, u.Path)
		if len(out) == 3 {
			return out
		}
	}
	return out
}

func appendIfMissing(in []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return in
	}
	for _, existing := range in {
		if strings.EqualFold(existing, v) {
			return in
		}
	}
	return append(in, v)
}

func uniqueStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = appendIfMissing(out, v)
	}
	sort.Strings(out)
	return out
}

func normalizeHost(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(v, ".")))
}

func hostsFromSPNs(spns []string) []string {
	out := make([]string, 0)
	for _, spn := range spns {
		spn = strings.TrimSpace(spn)
		if spn == "" {
			continue
		}
		parts := strings.SplitN(spn, "/", 2)
		if len(parts) != 2 {
			continue
		}
		hostPart := parts[1]
		if idx := strings.Index(hostPart, ":"); idx > 0 {
			hostPart = hostPart[:idx]
		}
		if idx := strings.Index(hostPart, "/"); idx > 0 {
			hostPart = hostPart[:idx]
		}
		hostPart = normalizeHost(hostPart)
		if hostPart == "" {
			continue
		}
		out = appendIfMissing(out, hostPart)
	}
	return out
}

func isDCHost(dn, name string) bool {
	lowerDN := strings.ToLower(dn)
	lowerName := strings.ToLower(name)
	return strings.Contains(lowerDN, "ou=domain controllers,") || strings.HasPrefix(lowerName, "dc")
}

func chooseFirst(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
