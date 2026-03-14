package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	ldapclient "argus/internal/ldap"
	"argus/internal/models"

	"github.com/go-ldap/ldap/v3"
)

func PrivMapReview(client *ldapclient.Client, cfg models.Config) (models.PrivMapResult, error) {
	groups, err := client.SearchPrivilegedGroupEntries()
	if err != nil {
		return models.PrivMapResult{}, err
	}

	adminNameRegex := cfg.AdminNameRegex
	if strings.TrimSpace(adminNameRegex) == "" {
		adminNameRegex = `(?i)(^adm-|admin|svc|service|sql|backup|sa_)`
	}
	adminNameRe, err := regexp.Compile(adminNameRegex)
	if err != nil {
		return models.PrivMapResult{}, fmt.Errorf("compile admin-name-regex: %w", err)
	}

	res := models.PrivMapResult{
		Domain:             cfg.Domain,
		AdminNameRegexUsed: adminNameRegex,
		Groups:             make([]models.PrivilegedGroup, 0, len(groups)),
	}

	for _, g := range groups {
		pg, err := expandPrivilegedGroup(client, g, adminNameRe)
		if err != nil {
			return models.PrivMapResult{}, err
		}
		res.Groups = append(res.Groups, pg)
		res.TotalUsers += len(pg.PrivilegedUsers)
		res.TotalNestedGroups += len(pg.NestedGroups)
		res.TotalServiceAccts += len(pg.ServiceAccounts)
		res.TotalReviewUsers += len(pg.ReviewCandidates)
	}

	sort.Slice(res.Groups, func(i, j int) bool {
		return res.Groups[i].Name < res.Groups[j].Name
	})
	res.TotalPrivGroups = len(res.Groups)

	return res, nil
}

func expandPrivilegedGroup(client *ldapclient.Client, group *ldap.Entry, adminNameRe *regexp.Regexp) (models.PrivilegedGroup, error) {
	out := models.PrivilegedGroup{
		Name:              group.GetAttributeValue("cn"),
		DN:                group.GetAttributeValue("distinguishedName"),
		DirectMemberCount: len(group.GetAttributeValues("member")),
	}

	visitedGroups := map[string]struct{}{}
	visitedUsers := map[string]struct{}{}

	var walk func(groupDN string, path []string) error
	walk = func(groupDN string, path []string) error {
		if _, seen := visitedGroups[groupDN]; seen {
			return nil
		}
		visitedGroups[groupDN] = struct{}{}

		g, err := client.GetEntryByDN(groupDN, []string{"cn", "distinguishedName", "member"})
		if err != nil {
			return err
		}

		for _, memberDN := range g.GetAttributeValues("member") {
			member, err := client.GetEntryByDN(memberDN, []string{
				"cn",
				"displayName",
				"distinguishedName",
				"objectClass",
				"sAMAccountName",
				"userPrincipalName",
				"userAccountControl",
				"servicePrincipalName",
			})
			if err != nil {
				continue
			}

			memberName := pickName(member)
			memberPathSlice := append(append([]string{}, path...), memberName)
			memberPath := strings.Join(memberPathSlice, " -> ")

			if hasObjectClass(member, "group") {
				if memberDN != out.DN {
					out.NestedGroups = append(out.NestedGroups, models.NestedGroup{
						Name: memberName,
						DN:   memberDN,
						Path: memberPath,
					})
					if err := walk(memberDN, memberPathSlice); err != nil {
						return err
					}
				}
				continue
			}

			if hasObjectClass(member, "user") ||
				hasObjectClass(member, "msDS-GroupManagedServiceAccount") ||
				hasObjectClass(member, "msDS-ManagedServiceAccount") {
				if _, seen := visitedUsers[memberDN]; seen {
					continue
				}
				visitedUsers[memberDN] = struct{}{}

				account := models.Account{
					Name:    memberName,
					UPN:     member.GetAttributeValue("userPrincipalName"),
					DN:      memberDN,
					Path:    memberPath,
					Enabled: isEnabled(member),
					Kind:    "user",
				}

				if isServiceAccount(member) {
					account.Kind = "service"
					out.ServiceAccounts = append(out.ServiceAccounts, account)
				} else {
					out.PrivilegedUsers = append(out.PrivilegedUsers, account)
					sam := strings.ToLower(member.GetAttributeValue("sAMAccountName"))
					if !adminNameRe.MatchString(sam) {
						out.ReviewCandidates = append(out.ReviewCandidates, account)
					}
				}
			}
		}

		return nil
	}

	if err := walk(out.DN, []string{out.Name}); err != nil {
		return models.PrivilegedGroup{}, err
	}

	sort.Slice(out.NestedGroups, func(i, j int) bool { return out.NestedGroups[i].Path < out.NestedGroups[j].Path })
	sort.Slice(out.PrivilegedUsers, func(i, j int) bool { return out.PrivilegedUsers[i].Name < out.PrivilegedUsers[j].Name })
	sort.Slice(out.ServiceAccounts, func(i, j int) bool { return out.ServiceAccounts[i].Name < out.ServiceAccounts[j].Name })
	sort.Slice(out.ReviewCandidates, func(i, j int) bool { return out.ReviewCandidates[i].Name < out.ReviewCandidates[j].Name })

	return out, nil
}

func pickName(e *ldap.Entry) string {
	if v := strings.TrimSpace(e.GetAttributeValue("sAMAccountName")); v != "" {
		return v
	}
	if v := strings.TrimSpace(e.GetAttributeValue("displayName")); v != "" {
		return v
	}
	if v := strings.TrimSpace(e.GetAttributeValue("cn")); v != "" {
		return v
	}
	return e.DN
}

func hasObjectClass(e *ldap.Entry, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, v := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func isServiceAccount(e *ldap.Entry) bool {
	if hasObjectClass(e, "msDS-GroupManagedServiceAccount") || hasObjectClass(e, "msDS-ManagedServiceAccount") {
		return true
	}
	if len(e.GetAttributeValues("servicePrincipalName")) > 0 {
		return true
	}
	return strings.HasSuffix(strings.ToLower(e.GetAttributeValue("sAMAccountName")), "$")
}

func isEnabled(e *ldap.Entry) bool {
	uac := 0
	_, _ = fmt.Sscanf(e.GetAttributeValue("userAccountControl"), "%d", &uac)
	return (uac & 2) == 0
}
