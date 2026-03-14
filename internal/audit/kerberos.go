package audit

import (
	"argus/internal/models"
	"strings"
	"time"
)

const (
	uacDontRequirePreauth = 0x00400000
	uacTrustedForDeleg    = 0x00080000
)

func KerberosReview(cfg models.Config, users []models.UserRecord) models.KerberosResult {
	var result models.KerberosResult

	for _, u := range users {
		if u.SAMAccountName == "" {
			continue
		}

		if hasUACFlag(u.UserAccountControl, uacDontRequirePreauth) {
			result.PreAuthDisabled = append(result.PreAuthDisabled, models.KerberosFinding{
				SAMAccountName: u.SAMAccountName,
				DN:             u.DistinguishedName,
				Reason:         "Kerberos pre-authentication is disabled",
			})
		}

		if len(u.ServicePrincipalName) > 0 {
			result.SPNAccounts = append(result.SPNAccounts, models.KerberosFinding{
				SAMAccountName: u.SAMAccountName,
				DN:             u.DistinguishedName,
				Reason:         "Account has one or more SPNs registered",
				SPNs:           u.ServicePrincipalName,
			})
		}

		if len(u.ServicePrincipalName) > 0 && isPrivileged(u) {
			result.PrivilegedSPNAccounts = append(result.PrivilegedSPNAccounts, models.KerberosFinding{
				SAMAccountName: u.SAMAccountName,
				DN:             u.DistinguishedName,
				Reason:         "Privileged account has one or more SPNs registered",
				SPNs:           u.ServicePrincipalName,
			})
		}

		if usesLegacyEncryption(u.MSEncryptionTypes) {
			result.LegacyEncryption = append(result.LegacyEncryption, models.KerberosFinding{
				SAMAccountName: u.SAMAccountName,
				DN:             u.DistinguishedName,
				Reason:         "Legacy or weak Kerberos encryption configuration detected",
			})
		}

		if cfg.PasswordAge {
			if isServiceLike(u) && isOldPassword(u.PwdLastSet, 180) {
				result.PasswordAgeReview = append(result.PasswordAgeReview, models.KerberosFinding{
					SAMAccountName: u.SAMAccountName,
					DN:             u.DistinguishedName,
					Reason:         "Service-like account with password older than 180 days",
					SPNs:           u.ServicePrincipalName,
				})
			}
		}
	}

	if cfg.PrivilegedOnly {
		result.SPNAccounts = nil
		result.PreAuthDisabled = filterPrivileged(result.PreAuthDisabled, users)
		result.LegacyEncryption = filterPrivileged(result.LegacyEncryption, users)
		result.PasswordAgeReview = filterPrivileged(result.PasswordAgeReview, users)
	}

	return result
}

func hasUACFlag(v, flag int) bool {
	return v&flag == flag
}

func usesLegacyEncryption(v int) bool {
	if v == 0 {
		return true
	}
	hasAES := v&0x08 == 0x08 || v&0x10 == 0x10
	return !hasAES
}

func isOldPassword(t time.Time, days int) bool {
	if t.IsZero() {
		return false
	}
	return time.Since(t) > time.Duration(days)*24*time.Hour
}

func isPrivileged(u models.UserRecord) bool {
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
	if hasUACFlag(u.UserAccountControl, uacTrustedForDeleg) {
		return true
	}
	return false
}

func isServiceLike(u models.UserRecord) bool {
	if len(u.ServicePrincipalName) > 0 {
		return true
	}
	name := strings.ToLower(u.SAMAccountName)
	return strings.HasPrefix(name, "svc_") ||
		strings.HasSuffix(name, "_svc") ||
		strings.Contains(name, "service")
}

func filterPrivileged(findings []models.KerberosFinding, users []models.UserRecord) []models.KerberosFinding {
	index := make(map[string]bool, len(users))
	for _, u := range users {
		if isPrivileged(u) {
			index[strings.ToLower(u.SAMAccountName)] = true
		}
	}

	out := make([]models.KerberosFinding, 0)
	for _, f := range findings {
		if index[strings.ToLower(f.SAMAccountName)] {
			out = append(out, f)
		}
	}
	return out
}
