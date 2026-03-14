package audit

import (
	"argus/internal/models"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

const (
	aceTypeAccessAllowed       = 0x00
	aceTypeAccessAllowedObject = 0x05

	aceFlagInherited = 0x10

	accessAllowedObjectTypePresent          = 0x00000001
	accessAllowedInheritedObjectTypePresent = 0x00000002

	rightDSCreateChild     = 0x00000001
	rightDSDeleteChild     = 0x00000002
	rightDSReadProperty    = 0x00000010
	rightDSWriteProperty   = 0x00000020
	rightDSControlAccess   = 0x00000100
	rightWriteDACL         = 0x00040000
	rightWriteOwner        = 0x00080000
	rightGenericWrite      = 0x40000000
	rightGenericAll        = 0x10000000
)

const (
	guidResetPassword = "00299570-246d-11d0-a768-00aa006e0529"
	guidMember        = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	zeroGUID          = "00000000-0000-0000-0000-000000000000"
)

type parsedACE struct {
	SID            string
	Mask           uint32
	ObjectTypeGUID string
	Inherited      bool
}

func ACLExposureReview(targets []models.ACLExposureTarget, principalSIDMap map[string]string, privilegedOnly bool) models.ACLExposureResult {
	result := models.ACLExposureResult{
		Findings: make([]models.ACLExposureFinding, 0),
	}

	seen := make(map[string]struct{})

	for _, target := range targets {
		if len(target.SecurityDescriptor) == 0 {
			continue
		}
		if privilegedOnly && !isHighValueTarget(target) {
			continue
		}

		aces, err := parseDACL(target.SecurityDescriptor)
		if err != nil {
			continue
		}

		for _, ace := range aces {
			if shouldIgnorePrincipalSID(ace.SID) {
				continue
			}

			principal := ace.SID
			if resolved, ok := principalSIDMap[ace.SID]; ok && strings.TrimSpace(resolved) != "" {
				principal = resolved
			}

			matches := evaluateDangerousRights(target, ace)
			for _, match := range matches {
				key := strings.ToLower(strings.Join([]string{
					target.DN,
					ace.SID,
					match.Right,
				}, "|"))

				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}

				result.Findings = append(result.Findings, models.ACLExposureFinding{
					Object:         target.Name,
					ObjectType:     strings.Title(target.ObjectType),
					DN:             target.DN,
					Principal:      principal,
					PrincipalSID:   ace.SID,
					Right:          match.Right,
					Severity:       match.Severity,
					Reason:         match.Reason,
					Inherited:      ace.Inherited,
					ObjectTypeGUID: ace.ObjectTypeGUID,
				})
			}
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		ri := severityRank(result.Findings[i].Severity)
		rj := severityRank(result.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if result.Findings[i].Object != result.Findings[j].Object {
			return result.Findings[i].Object < result.Findings[j].Object
		}
		if result.Findings[i].Principal != result.Findings[j].Principal {
			return result.Findings[i].Principal < result.Findings[j].Principal
		}
		return result.Findings[i].Right < result.Findings[j].Right
	})

	return result
}

type rightMatch struct {
	Right    string
	Severity models.Severity
	Reason   string
}

func evaluateDangerousRights(target models.ACLExposureTarget, ace parsedACE) []rightMatch {
	var out []rightMatch

	if ace.Mask&rightGenericAll != 0 {
		out = append(out, rightMatch{
			Right:    "GenericAll",
			Severity: models.SeverityCritical,
			Reason:   aclExposureReason(target, "GenericAll"),
		})
	}

	if ace.Mask&rightWriteOwner != 0 {
		out = append(out, rightMatch{
			Right:    "WriteOwner",
			Severity: models.SeverityCritical,
			Reason:   aclExposureReason(target, "WriteOwner"),
		})
	}

	if ace.Mask&rightWriteDACL != 0 {
		out = append(out, rightMatch{
			Right:    "WriteDACL",
			Severity: models.SeverityHigh,
			Reason:   aclExposureReason(target, "WriteDACL"),
		})
	}

	if ace.Mask&rightGenericWrite != 0 {
		out = append(out, rightMatch{
			Right:    "GenericWrite",
			Severity: models.SeverityHigh,
			Reason:   aclExposureReason(target, "GenericWrite"),
		})
	}

	if strings.EqualFold(target.ObjectType, "group") &&
		ace.Mask&rightDSWriteProperty != 0 &&
		strings.EqualFold(ace.ObjectTypeGUID, guidMember) {
		out = append(out, rightMatch{
			Right:    "AddMember",
			Severity: models.SeverityHigh,
			Reason:   aclExposureReason(target, "AddMember"),
		})
	}

	if strings.EqualFold(target.ObjectType, "user") &&
		ace.Mask&rightDSControlAccess != 0 &&
		strings.EqualFold(ace.ObjectTypeGUID, guidResetPassword) {
		out = append(out, rightMatch{
			Right:    "ResetPassword",
			Severity: models.SeverityMedium,
			Reason:   aclExposureReason(target, "ResetPassword"),
		})
	}

	if ace.Mask&rightDSControlAccess != 0 &&
		(ace.ObjectTypeGUID == "" || strings.EqualFold(ace.ObjectTypeGUID, zeroGUID)) {
		out = append(out, rightMatch{
			Right:    "AllExtendedRights",
			Severity: models.SeverityMedium,
			Reason:   aclExposureReason(target, "AllExtendedRights"),
		})
	}

	return out
}

func aclExposureReason(target models.ACLExposureTarget, right string) string {
	targetLabel := aclExposureTargetLabel(target)

	switch right {
	case "GenericAll":
		return fmt.Sprintf("full control over %s", targetLabel)
	case "WriteOwner":
		return fmt.Sprintf("can take ownership of %s and re-delegate access", targetLabel)
	case "WriteDACL":
		return fmt.Sprintf("can modify the DACL on %s and grant broader control", targetLabel)
	case "GenericWrite":
		return fmt.Sprintf("can modify important attributes on %s", targetLabel)
	case "AddMember":
		return fmt.Sprintf("can add members to %s", targetLabel)
	case "ResetPassword":
		return fmt.Sprintf("can reset the password on %s", targetLabel)
	case "AllExtendedRights":
		return fmt.Sprintf("has extended rights over %s that can enable high-impact control", targetLabel)
	default:
		return fmt.Sprintf("dangerous delegated control over %s", targetLabel)
	}
}

func aclExposureTargetLabel(target models.ACLExposureTarget) string {
	if isHighValueTarget(target) {
		switch strings.ToLower(target.ObjectType) {
		case "group":
			return "privileged group"
		case "domain":
			return "domain root"
		case "gpo":
			return "group policy object"
		case "ou":
			return "high-value organizational unit"
		case "computer":
			return "high-value computer object"
		case "user":
			return "high-value user object"
		}
	}

	switch strings.ToLower(target.ObjectType) {
	case "group":
		return fmt.Sprintf("group %s", target.Name)
	case "user":
		return fmt.Sprintf("user %s", target.Name)
	case "computer":
		return fmt.Sprintf("computer %s", target.Name)
	case "ou":
		return fmt.Sprintf("OU %s", target.Name)
	case "gpo":
		return fmt.Sprintf("GPO %s", target.Name)
	case "domain":
		return "domain root"
	default:
		return fmt.Sprintf("%s %s", target.ObjectType, target.Name)
	}
}

func isHighValueTarget(target models.ACLExposureTarget) bool {
	name := strings.ToLower(strings.TrimSpace(target.Name))
	dn := strings.ToLower(target.DN)

	if strings.EqualFold(target.ObjectType, "domain") {
		return true
	}

	if strings.EqualFold(target.ObjectType, "gpo") {
		return true
	}

	if strings.EqualFold(target.ObjectType, "ou") && name == "domain controllers" {
		return true
	}

	if strings.EqualFold(target.ObjectType, "computer") && strings.Contains(dn, "ou=domain controllers,") {
		return true
	}

	if strings.EqualFold(target.ObjectType, "user") {
		if name == "administrator" || name == "krbtgt" {
			return true
		}
	}

	if strings.EqualFold(target.ObjectType, "group") {
		highValueGroups := map[string]struct{}{
			"domain admins":               {},
			"enterprise admins":           {},
			"schema admins":               {},
			"administrators":              {},
			"account operators":           {},
			"server operators":            {},
			"backup operators":            {},
			"print operators":             {},
			"group policy creator owners": {},
			"dnsadmins":                   {},
			"domain controllers":          {},
			"enterprise key admins":       {},
			"key admins":                  {},
		}
		_, ok := highValueGroups[name]
		return ok
	}

	return false
}

func shouldIgnorePrincipalSID(sid string) bool {
	ignored := map[string]struct{}{
		"S-1-3-0":      {},
		"S-1-5-9":      {},
		"S-1-5-10":     {},
		"S-1-5-18":     {},
		"S-1-5-32-544": {},
		"S-1-5-32-548": {},
		"S-1-5-32-549": {},
		"S-1-5-32-550": {},
		"S-1-5-32-551": {},
	}
	_, ok := ignored[sid]
	return ok
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

func parseDACL(sd []byte) ([]parsedACE, error) {
	if len(sd) < 20 {
		return nil, fmt.Errorf("security descriptor too short")
	}

	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 {
		return nil, nil
	}
	if daclOffset+8 > len(sd) {
		return nil, fmt.Errorf("invalid dacl offset")
	}

	acl := sd[daclOffset:]
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	offset := 8

	out := make([]parsedACE, 0, aceCount)

	for i := 0; i < aceCount; i++ {
		if offset+4 > len(acl) {
			break
		}

		aceType := acl[offset]
		aceFlags := acl[offset+1]
		aceSize := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if aceSize < 8 || offset+aceSize > len(acl) {
			break
		}

		aceBytes := acl[offset : offset+aceSize]
		offset += aceSize

		if aceType != aceTypeAccessAllowed && aceType != aceTypeAccessAllowedObject {
			continue
		}

		mask := binary.LittleEndian.Uint32(aceBytes[4:8])
		sidOffset := 8
		objectTypeGUID := ""

		if aceType == aceTypeAccessAllowedObject {
			if len(aceBytes) < 12 {
				continue
			}

			flags := binary.LittleEndian.Uint32(aceBytes[8:12])
			sidOffset = 12

			if flags&accessAllowedObjectTypePresent != 0 {
				if sidOffset+16 > len(aceBytes) {
					continue
				}
				objectTypeGUID = aceGUIDString(aceBytes[sidOffset : sidOffset+16])
				sidOffset += 16
			}

			if flags&accessAllowedInheritedObjectTypePresent != 0 {
				if sidOffset+16 > len(aceBytes) {
					continue
				}
				sidOffset += 16
			}
		}

		sid, ok := aceSIDToString(aceBytes[sidOffset:])
		if !ok {
			continue
		}

		out = append(out, parsedACE{
			SID:            sid,
			Mask:           mask,
			ObjectTypeGUID: strings.ToLower(objectTypeGUID),
			Inherited:      (aceFlags & aceFlagInherited) != 0,
		})
	}

	return out, nil
}

func aceSIDToString(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}

	revision := b[0]
	subAuthCount := int(b[1])
	if len(b) < 8+(subAuthCount*4) {
		return "", false
	}

	var authority uint64
	for i := 2; i < 8; i++ {
		authority <<= 8
		authority |= uint64(b[i])
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}
	offset := 8
	for i := 0; i < subAuthCount; i++ {
		subAuth := binary.LittleEndian.Uint32(b[offset : offset+4])
		parts = append(parts, fmt.Sprintf("%d", subAuth))
		offset += 4
	}

	return strings.Join(parts, "-"), true
}

func aceGUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}

	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])

	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1,
		d2,
		d3,
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15],
	)
}
