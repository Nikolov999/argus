package audit

import (
	"argus/internal/models"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

const (
	certACETypeAccessAllowed       = 0x00
	certACETypeAccessAllowedObject = 0x05

	certACEFlagInherited = 0x10

	certAccessAllowedObjectTypePresent          = 0x00000001
	certAccessAllowedInheritedObjectTypePresent = 0x00000002

	certRightEnroll       = 0x00000100
	certRightAutoEnroll   = 0x00000200
	certRightWriteDACL    = 0x00040000
	certRightWriteOwner   = 0x00080000
	certRightGenericAll   = 0x10000000
	certRightGenericWrite = 0x40000000
)

const (
	certNameFlagEnrolleeSuppliesSubject    = 0x00000001
	certNameFlagEnrolleeSuppliesSubjectAlt = 0x00010000
)

const (
	certEnrollFlagPendAllRequests = 0x00000002
	certEnrollFlagAutoEnrollment  = 0x00000020
	certEnrollFlagNoSecurityExt   = 0x00080000
)

const (
	oidClientAuth       = "1.3.6.1.5.5.7.3.2"
	oidPKINITClientAuth = "1.3.6.1.5.2.3.4"
	oidSmartcardLogon   = "1.3.6.1.4.1.311.20.2.2"
	oidAnyPurpose       = "2.5.29.37.0"
	oidCertificateRA    = "1.3.6.1.4.1.311.20.2.1"
)

type certParsedACE struct {
	SID       string
	Mask      uint32
	Inherited bool
}

func CertSurface(templates []models.CertTemplate, principalSIDMap map[string]string) models.CertResult {
	result := models.CertResult{
		Templates: make([]models.CertFinding, 0, len(templates)),
	}

	for _, t := range templates {
		finding := evaluateCertTemplate(t, principalSIDMap)
		result.Templates = append(result.Templates, finding)
	}

	sort.Slice(result.Templates, func(i, j int) bool {
		if result.Templates[i].RiskScore != result.Templates[j].RiskScore {
			return result.Templates[i].RiskScore > result.Templates[j].RiskScore
		}
		if result.Templates[i].Name != result.Templates[j].Name {
			return result.Templates[i].Name < result.Templates[j].Name
		}
		return result.Templates[i].DisplayName < result.Templates[j].DisplayName
	})

	return result
}

func evaluateCertTemplate(t models.CertTemplate, principalSIDMap map[string]string) models.CertFinding {
	labels := make([]string, 0)
	notes := make([]string, 0)
	riskScore := 0

	enrollPrincipals, autoEnrollPrincipals, dangerousACLPrincipals := certTemplatePrincipals(t, principalSIDMap)
	lowPrivEnroll := len(enrollPrincipals) > 0
	lowPrivAutoEnroll := len(autoEnrollPrincipals) > 0
	lowPrivDangerousACL := len(dangerousACLPrincipals) > 0

	hasClientAuth := certHasAnyEKU(t.EKUs, oidClientAuth, oidPKINITClientAuth, oidSmartcardLogon)
	hasAnyPurpose := certHasAnyEKU(t.EKUs, oidAnyPurpose)
	hasEnrollmentAgent := certHasAnyEKU(t.EKUs, oidCertificateRA)
	hasNoEKU := len(t.EKUs) == 0
	enrolleeSuppliesSubject := (t.NameFlag & certNameFlagEnrolleeSuppliesSubject) != 0
	enrolleeSuppliesSAN := (t.NameFlag & certNameFlagEnrolleeSuppliesSubjectAlt) != 0
	managerApproval := (t.EnrollmentFlag & certEnrollFlagPendAllRequests) != 0
	noSecurityExtension := (t.EnrollmentFlag & certEnrollFlagNoSecurityExt) != 0
	autoEnrollmentEnabled := (t.EnrollmentFlag & certEnrollFlagAutoEnrollment) != 0
	raSignatureCount := t.RASignatureCount
	noAuthorizedSignatures := raSignatureCount == 0

	if lowPrivEnroll && hasClientAuth && enrolleeSuppliesSubject && !managerApproval && noAuthorizedSignatures {
		labels = append(labels, "ESC1")
		riskScore += 100
		notes = append(notes, "Low-privileged principals can enroll in an authentication-capable template that allows requester-supplied subject data without approval gates.")
	}

	if lowPrivEnroll && hasAnyPurpose && !managerApproval {
		labels = append(labels, "ESC2")
		riskScore += 90
		notes = append(notes, "Low-privileged principals can enroll in a template with Any Purpose EKU.")
	}

	if lowPrivEnroll && hasNoEKU && !managerApproval {
		labels = append(labels, "ESC2")
		riskScore += 90
		notes = append(notes, "Low-privileged principals can enroll in a template with no EKU restriction, making it usable for multiple purposes.")
	}

	if lowPrivEnroll && hasEnrollmentAgent && !managerApproval {
		labels = append(labels, "ESC3-Candidate")
		riskScore += 75
		notes = append(notes, "Low-privileged principals can enroll in a certificate request agent template. Validate issuance requirements and on-behalf-of restrictions.")
	}

	if lowPrivEnroll && hasClientAuth && noSecurityExtension && !managerApproval && noAuthorizedSignatures {
		labels = append(labels, "ESC9-Candidate")
		riskScore += 80
		notes = append(notes, "Authentication-capable template omits the security extension. Validate strong mapping posture and patch level before treating as exploitable.")
	}

	if lowPrivEnroll && hasClientAuth {
		riskScore += 35
		notes = append(notes, "Low-privileged principals can enroll in an authentication-capable template.")
	}

	if lowPrivEnroll && hasAnyPurpose {
		riskScore += 20
	}

	if lowPrivEnroll && hasNoEKU {
		riskScore += 20
	}

	if enrolleeSuppliesSubject {
		riskScore += 15
		notes = append(notes, "Template allows requester-supplied subject values.")
	}

	if enrolleeSuppliesSAN {
		riskScore += 20
		notes = append(notes, "Template allows requester-supplied subject alternative names.")
	}

	if lowPrivAutoEnroll && autoEnrollmentEnabled {
		labels = append(labels, "LowPrivAutoEnroll")
		riskScore += 25
		notes = append(notes, "Low-privileged principals can automatically enroll for this template.")
	}

	if lowPrivDangerousACL {
		labels = append(labels, "DangerousTemplateACL")
		riskScore += 40
		notes = append(notes, "Low-privileged principals can modify or fully control the template ACL, enabling direct abuse or silent weakening.")
	}

	if managerApproval {
		riskScore -= 15
		notes = append(notes, "Manager approval is required before issuance.")
	}

	if !noAuthorizedSignatures {
		riskScore -= 10
		notes = append(notes, fmt.Sprintf("Authorized signatures required: %d.", raSignatureCount))
	}

	if riskScore < 0 {
		riskScore = 0
	}

	labels = certUniqueSorted(labels)
	notes = certUniqueSorted(notes)

	riskSummary := certRiskSummary(labels, notes, t)

	return models.CertFinding{
		Name:                   t.Name,
		DisplayName:            t.DisplayName,
		EKUs:                   t.EKUs,
		EnrollmentFlag:         t.EnrollmentFlag,
		NameFlag:               t.NameFlag,
		RASignatureCount:       t.RASignatureCount,
		SchemaVersion:          t.SchemaVersion,
		EnrollPrincipals:       enrollPrincipals,
		AutoEnrollPrincipals:   autoEnrollPrincipals,
		DangerousACLPrincipals: dangerousACLPrincipals,
		Labels:                 labels,
		RiskScore:              riskScore,
		RiskSummary:            riskSummary,
		Notes:                  notes,
	}
}

func certTemplatePrincipals(t models.CertTemplate, principalSIDMap map[string]string) ([]string, []string, []string) {
	if len(t.SecurityDescriptor) == 0 {
		return nil, nil, nil
	}

	aces, err := certParseDACL(t.SecurityDescriptor)
	if err != nil {
		return nil, nil, nil
	}

	enrollSet := map[string]struct{}{}
	autoEnrollSet := map[string]struct{}{}
	dangerSet := map[string]struct{}{}

	for _, ace := range aces {
		if !certIsLowPrivilegeSID(ace.SID) {
			continue
		}

		principal := ace.SID
		if resolved, ok := principalSIDMap[ace.SID]; ok && strings.TrimSpace(resolved) != "" {
			principal = resolved
		}

		if ace.Mask&certRightEnroll != 0 {
			enrollSet[principal] = struct{}{}
		}
		if ace.Mask&certRightAutoEnroll != 0 {
			autoEnrollSet[principal] = struct{}{}
		}
		if ace.Mask&certRightWriteDACL != 0 || ace.Mask&certRightWriteOwner != 0 || ace.Mask&certRightGenericAll != 0 || ace.Mask&certRightGenericWrite != 0 {
			dangerSet[principal] = struct{}{}
		}
	}

	return certSetToSortedSlice(enrollSet), certSetToSortedSlice(autoEnrollSet), certSetToSortedSlice(dangerSet)
}

func certRiskSummary(labels, notes []string, t models.CertTemplate) string {
	if len(labels) > 0 {
		return fmt.Sprintf("%s detected on template %s.", strings.Join(labels, ", "), certTemplateName(t))
	}
	if len(notes) > 0 {
		return notes[0]
	}
	return "Review enrollment scope, EKUs, issuance requirements, and template ACLs."
}

func certTemplateName(t models.CertTemplate) string {
	if strings.TrimSpace(t.DisplayName) != "" {
		return t.DisplayName
	}
	return t.Name
}

func certHasAnyEKU(ekus []string, candidates ...string) bool {
	for _, eku := range ekus {
		for _, candidate := range candidates {
			if strings.EqualFold(strings.TrimSpace(eku), candidate) {
				return true
			}
		}
	}
	return false
}

func certUniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func certSetToSortedSlice(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for item := range in {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func certIsLowPrivilegeSID(sid string) bool {
	sid = strings.TrimSpace(strings.ToUpper(sid))
	if sid == "" {
		return false
	}

	lowPriv := map[string]struct{}{
		"S-1-1-0":      {},
		"S-1-5-11":     {},
		"S-1-5-32-545": {},
	}

	if _, ok := lowPriv[sid]; ok {
		return true
	}

	if strings.HasSuffix(sid, "-513") && strings.HasPrefix(sid, "S-1-5-21-") {
		return true
	}

	return false
}

func certParseDACL(sd []byte) ([]certParsedACE, error) {
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
	out := make([]certParsedACE, 0, aceCount)

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

		if aceType != certACETypeAccessAllowed && aceType != certACETypeAccessAllowedObject {
			continue
		}

		mask := binary.LittleEndian.Uint32(aceBytes[4:8])
		sidOffset := 8

		if aceType == certACETypeAccessAllowedObject {
			if len(aceBytes) < 12 {
				continue
			}
			flags := binary.LittleEndian.Uint32(aceBytes[8:12])
			sidOffset = 12
			if flags&certAccessAllowedObjectTypePresent != 0 {
				sidOffset += 16
			}
			if flags&certAccessAllowedInheritedObjectTypePresent != 0 {
				sidOffset += 16
			}
		}

		sid, ok := certACESIDToString(aceBytes[sidOffset:])
		if !ok {
			continue
		}

		out = append(out, certParsedACE{
			SID:       sid,
			Mask:      mask,
			Inherited: (aceFlags & certACEFlagInherited) != 0,
		})
	}

	return out, nil
}

func certACESIDToString(b []byte) (string, bool) {
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
