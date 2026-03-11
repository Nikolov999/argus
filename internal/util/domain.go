package util

import (
	"fmt"
	"strings"
	"time"
)

func DomainToBaseDN(domain string) string {
	parts := strings.Split(strings.TrimSpace(domain), ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, "DC="+p)
	}
	return strings.Join(out, ",")
}

func BuildLDAPURL(dc string, useLDAPS bool) string {
	if useLDAPS {
		return fmt.Sprintf("ldaps://%s:636", dc)
	}
	return fmt.Sprintf("ldap://%s:389", dc)
}

func FileTimestampToTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	const windowsToUnixOffset = 116444736000000000
	const ticksPerSecond = 10000000

	unix100ns := v - windowsToUnixOffset
	sec := unix100ns / ticksPerSecond
	nsec := (unix100ns % ticksPerSecond) * 100

	return time.Unix(sec, nsec).UTC()
}

func BoolWord(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}
