package ldapclient

import (
	"argus/internal/models"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type Client struct {
	conn *ldap.Conn
	cfg  models.Config
}

func New(cfg models.Config) (*Client, error) {
	var (
		conn *ldap.Conn
		err  error
	)

	if cfg.UseLDAPS {
		conn, err = ldap.DialURL(
			cfg.LDAPURL,
			ldap.DialWithTLSConfig(&tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			}),
		)
	} else {
		conn, err = ldap.DialURL(cfg.LDAPURL)
	}

	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}

	conn.SetTimeout(time.Duration(cfg.TimeoutSeconds) * time.Second)

	if cfg.Username != "" && cfg.Password != "" {
		if err := conn.Bind(cfg.Username, cfg.Password); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("bind: %w", err)
		}
	}

	return &Client{conn: conn, cfg: cfg}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *Client) CountByFilter(filter string) (int, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return 0, err
	}
	return len(res.Entries), nil
}

func (c *Client) SearchUsers() ([]models.UserRecord, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{
			"sAMAccountName",
			"distinguishedName",
			"servicePrincipalName",
			"userAccountControl",
			"msDS-SupportedEncryptionTypes",
			"pwdLastSet",
			"memberOf",
			"adminCount",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.UserRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
		enc, _ := strconv.Atoi(e.GetAttributeValue("msDS-SupportedEncryptionTypes"))
		adminCount, _ := strconv.Atoi(e.GetAttributeValue("adminCount"))
		pwdLastSetRaw, _ := strconv.ParseInt(e.GetAttributeValue("pwdLastSet"), 10, 64)

		out = append(out, models.UserRecord{
			SAMAccountName:       e.GetAttributeValue("sAMAccountName"),
			DistinguishedName:    e.GetAttributeValue("distinguishedName"),
			ServicePrincipalName: e.GetAttributeValues("servicePrincipalName"),
			UserAccountControl:   uac,
			MSEncryptionTypes:    enc,
			AdminCount:           adminCount,
			PwdLastSet:           fileTimeToTime(pwdLastSetRaw),
			MemberOf:             e.GetAttributeValues("memberOf"),
		})
	}

	return out, nil
}

func (c *Client) SearchGPOs() ([]models.GPORecord, error) {
	base := "CN=Policies,CN=System," + c.cfg.BaseDN
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=groupPolicyContainer)",
		[]string{
			"name",
			"displayName",
			"distinguishedName",
			"gPCFileSysPath",
			"versionNumber",
			"flags",
			"whenChanged",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.GPORecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, models.GPORecord{
			Name:        e.GetAttributeValue("name"),
			DisplayName: e.GetAttributeValue("displayName"),
			DN:          e.GetAttributeValue("distinguishedName"),
			FileSysPath: e.GetAttributeValue("gPCFileSysPath"),
			Version:     e.GetAttributeValue("versionNumber"),
			WhenChanged: e.GetAttributeValue("whenChanged"),
			Flags:       e.GetAttributeValue("flags"),
		})
	}
	return out, nil
}

func (c *Client) SearchTrusts() ([]models.TrustRecord, error) {
	base := "CN=System," + c.cfg.BaseDN
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=trustedDomain)",
		[]string{
			"trustPartner",
			"trustDirection",
			"trustType",
			"flatName",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.TrustRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		dir, _ := strconv.Atoi(e.GetAttributeValue("trustDirection"))
		typ, _ := strconv.Atoi(e.GetAttributeValue("trustType"))
		out = append(out, models.TrustRecord{
			Partner:   e.GetAttributeValue("trustPartner"),
			Direction: dir,
			Type:      typ,
			FlatName:  e.GetAttributeValue("flatName"),
		})
	}
	return out, nil
}

func (c *Client) SearchDelegationPrincipals() ([]models.DelegationPrincipal, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(&(objectCategory=person)(objectClass=user))(objectClass=computer))",
		[]string{
			"sAMAccountName",
			"distinguishedName",
			"userAccountControl",
			"msDS-AllowedToDelegateTo",
			"msDS-AllowedToActOnBehalfOfOtherIdentity",
			"servicePrincipalName",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.DelegationPrincipal, 0, len(res.Entries))
	for _, e := range res.Entries {
		uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
		rawRbcd := e.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")

		out = append(out, models.DelegationPrincipal{
			SAMAccountName:       e.GetAttributeValue("sAMAccountName"),
			DN:                   e.GetAttributeValue("distinguishedName"),
			UAC:                  uac,
			AllowedToDelegateTo:  e.GetAttributeValues("msDS-AllowedToDelegateTo"),
			HasRBCDDescriptor:    len(rawRbcd) > 0,
			ServicePrincipalName: e.GetAttributeValues("servicePrincipalName"),
		})
	}

	return out, nil
}

func (c *Client) SearchCertTemplates() ([]models.CertTemplate, error) {
	base := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + c.cfg.BaseDN
	ctrl := &ControlMicrosoftSDFlags{Flags: 0x04}

	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"cn",
			"displayName",
			"pKIExtendedKeyUsage",
			"msPKI-Enrollment-Flag",
			"msPKI-Certificate-Name-Flag",
			"msPKI-RA-Signature",
			"msPKI-Template-Schema-Version",
			"nTSecurityDescriptor",
		},
		[]ldap.Control{ctrl},
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.CertTemplate, 0, len(res.Entries))
	for _, e := range res.Entries {
		enroll, _ := strconv.Atoi(e.GetAttributeValue("msPKI-Enrollment-Flag"))
		nameFlag, _ := strconv.Atoi(e.GetAttributeValue("msPKI-Certificate-Name-Flag"))
		raSignatures, _ := strconv.Atoi(e.GetAttributeValue("msPKI-RA-Signature"))
		schemaVersion, _ := strconv.Atoi(e.GetAttributeValue("msPKI-Template-Schema-Version"))

		out = append(out, models.CertTemplate{
			Name:               e.GetAttributeValue("cn"),
			DisplayName:        e.GetAttributeValue("displayName"),
			EKUs:               e.GetAttributeValues("pKIExtendedKeyUsage"),
			EnrollmentFlag:     enroll,
			NameFlag:           nameFlag,
			RASignatureCount:   raSignatures,
			SchemaVersion:      schemaVersion,
			SecurityDescriptor: e.GetRawAttributeValue("nTSecurityDescriptor"),
		})
	}

	return out, nil
}

func (c *Client) SearchPrivilegedGroups() ([]models.GroupRecord, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)(cn=Account Operators)(cn=Server Operators)(cn=Backup Operators))",
		[]string{
			"cn",
			"member",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.GroupRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, models.GroupRecord{
			Name:    e.GetAttributeValue("cn"),
			Members: e.GetAttributeValues("member"),
		})
	}
	return out, nil
}

func (c *Client) SearchComputers() ([]models.ComputerRecord, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=computer)",
		[]string{
			"name",
			"dNSHostName",
			"distinguishedName",
			"operatingSystem",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.ComputerRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, models.ComputerRecord{
			Name:        e.GetAttributeValue("name"),
			DNSHostName: e.GetAttributeValue("dNSHostName"),
			DN:          e.GetAttributeValue("distinguishedName"),
			OS:          e.GetAttributeValue("operatingSystem"),
		})
	}
	return out, nil
}

func (c *Client) SearchADIDNSARecordMap() (map[string][]string, error) {
	out := make(map[string][]string)

	bases := []string{
		"CN=MicrosoftDNS,DC=DomainDnsZones," + c.cfg.BaseDN,
		"CN=MicrosoftDNS,DC=ForestDnsZones," + c.cfg.BaseDN,
	}

	for _, base := range bases {
		req := ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=dnsNode)",
			[]string{
				"name",
				"distinguishedName",
				"dnsRecord",
			},
			nil,
		)

		res, err := c.conn.Search(req)
		if err != nil {
			// ForestDnsZones may not exist or may be inaccessible in some environments.
			// Only hard-fail if DomainDnsZones also fails and we gathered nothing.
			if strings.Contains(strings.ToLower(base), "domaindnszones") || len(out) == 0 {
				continue
			}
			continue
		}

		for _, e := range res.Entries {
			fqdn := dnsNodeFQDNFromDN(e.GetAttributeValue("distinguishedName"))
			short := strings.TrimSpace(e.GetAttributeValue("name"))

			rawRecords := e.GetRawAttributeValues("dnsRecord")
			for _, raw := range rawRecords {
				ip, ok := parseADIDNSARecord(raw)
				if !ok {
					continue
				}

				if fqdn != "" {
					addADIDNSMapping(out, fqdn, ip)
				}
				if short != "" && short != "@" {
					addADIDNSMapping(out, short, ip)
				}
			}
		}
	}

	return out, nil
}

func (c *Client) SearchACLTargets() ([]models.ACLTargetRecord, error) {
	out := make([]models.ACLTargetRecord, 0)

	searches := []struct {
		base   string
		scope  int
		filter string
		attrs  []string
		kind   string
	}{
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(&(objectCategory=person)(objectClass=user))",
			attrs:  []string{"sAMAccountName", "distinguishedName", "managedBy", "adminCount"},
			kind:   "user",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=group)",
			attrs:  []string{"cn", "distinguishedName", "managedBy", "adminCount"},
			kind:   "group",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=organizationalUnit)",
			attrs:  []string{"ou", "distinguishedName", "managedBy"},
			kind:   "ou",
		},
		{
			base:   "CN=Policies,CN=System," + c.cfg.BaseDN,
			scope:  ldap.ScopeSingleLevel,
			filter: "(objectClass=groupPolicyContainer)",
			attrs:  []string{"displayName", "name", "distinguishedName", "managedBy"},
			kind:   "gpo",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=computer)",
			attrs:  []string{"name", "distinguishedName", "managedBy", "adminCount"},
			kind:   "computer",
		},
	}

	for _, s := range searches {
		req := ldap.NewSearchRequest(
			s.base,
			s.scope,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			s.filter,
			s.attrs,
			nil,
		)

		res, err := c.conn.Search(req)
		if err != nil {
			return nil, err
		}

		for _, e := range res.Entries {
			adminCount, _ := strconv.Atoi(e.GetAttributeValue("adminCount"))
			name := firstNonEmpty(
				e.GetAttributeValue("sAMAccountName"),
				e.GetAttributeValue("cn"),
				e.GetAttributeValue("ou"),
				e.GetAttributeValue("displayName"),
				e.GetAttributeValue("name"),
			)

			out = append(out, models.ACLTargetRecord{
				ObjectType: s.kind,
				Name:       name,
				DN:         e.GetAttributeValue("distinguishedName"),
				ManagedBy:  e.GetAttributeValue("managedBy"),
				AdminCount: adminCount,
			})
		}
	}

	return out, nil
}

func (c *Client) SearchACLExposureTargets() ([]models.ACLExposureTarget, error) {
	out := make([]models.ACLExposureTarget, 0)

	searches := []struct {
		base   string
		scope  int
		filter string
		kind   string
	}{
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(&(objectCategory=person)(objectClass=user))",
			kind:   "user",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=group)",
			kind:   "group",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=computer)",
			kind:   "computer",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeWholeSubtree,
			filter: "(objectClass=organizationalUnit)",
			kind:   "ou",
		},
		{
			base:   "CN=Policies,CN=System," + c.cfg.BaseDN,
			scope:  ldap.ScopeSingleLevel,
			filter: "(objectClass=groupPolicyContainer)",
			kind:   "gpo",
		},
		{
			base:   c.cfg.BaseDN,
			scope:  ldap.ScopeBaseObject,
			filter: "(objectClass=domainDNS)",
			kind:   "domain",
		},
	}

	ctrl := &ControlMicrosoftSDFlags{Flags: 0x04}

	for _, s := range searches {
		req := ldap.NewSearchRequest(
			s.base,
			s.scope,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			s.filter,
			[]string{
				"nTSecurityDescriptor",
				"objectClass",
				"distinguishedName",
			},
			[]ldap.Control{ctrl},
		)

		res, err := c.conn.Search(req)
		if err != nil {
			return nil, err
		}

		for _, e := range res.Entries {
			dn := e.GetAttributeValue("distinguishedName")
			name := aclExposureNameFromDN(dn)
			if s.kind == "domain" {
				name = c.cfg.Domain
			}

			out = append(out, models.ACLExposureTarget{
				Name:               name,
				DN:                 dn,
				ObjectType:         s.kind,
				ObjectClass:        e.GetAttributeValues("objectClass"),
				SecurityDescriptor: e.GetRawAttributeValue("nTSecurityDescriptor"),
			})
		}
	}

	return out, nil
}

func (c *Client) SearchPrincipalSIDMap() (map[string]string, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=foreignSecurityPrincipal)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))",
		[]string{
			"objectSid",
			"sAMAccountName",
			"cn",
			"name",
			"distinguishedName",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := seedWellKnownSIDMap()

	for _, e := range res.Entries {
		raw := e.GetRawAttributeValue("objectSid")
		if len(raw) == 0 {
			continue
		}

		sid, ok := rawSIDToString(raw)
		if !ok {
			continue
		}

		name := firstNonEmpty(
			e.GetAttributeValue("sAMAccountName"),
			e.GetAttributeValue("cn"),
			e.GetAttributeValue("name"),
			aclExposureNameFromDN(e.GetAttributeValue("distinguishedName")),
		)
		if strings.TrimSpace(name) == "" {
			name = sid
		}

		out[sid] = name
	}

	return out, nil
}

type ControlMicrosoftSDFlags struct {
	Flags int
}

func (c *ControlMicrosoftSDFlags) GetControlType() string {
	return "1.2.840.113556.1.4.801"
}

func (c *ControlMicrosoftSDFlags) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			c.GetControlType(),
			"Control Type",
		),
	)

	sdFlags := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	sdFlags.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			uint64(c.Flags),
			"Flags",
		),
	)

	value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	value.Value = sdFlags.Bytes()
	packet.AppendChild(value)

	return packet
}

func (c *ControlMicrosoftSDFlags) String() string {
	return fmt.Sprintf("ControlMicrosoftSDFlags(%d)", c.Flags)
}

func aclExposureNameFromDN(dn string) string {
	if strings.TrimSpace(dn) == "" {
		return ""
	}

	first := dn
	if idx := strings.Index(first, ","); idx > 0 {
		first = first[:idx]
	}

	if idx := strings.Index(first, "="); idx > 0 && idx+1 < len(first) {
		return strings.TrimSpace(first[idx+1:])
	}

	return strings.TrimSpace(first)
}

func rawSIDToString(b []byte) (string, bool) {
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
		if offset+4 > len(b) {
			return "", false
		}
		subAuth := binary.LittleEndian.Uint32(b[offset : offset+4])
		parts = append(parts, fmt.Sprintf("%d", subAuth))
		offset += 4
	}

	return strings.Join(parts, "-"), true
}

func seedWellKnownSIDMap() map[string]string {
	return map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-3-0":      "Creator Owner",
		"S-1-5-7":      "Anonymous",
		"S-1-5-9":      "Enterprise Domain Controllers",
		"S-1-5-10":     "SELF",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-18":     "SYSTEM",
		"S-1-5-32-544": "Administrators",
		"S-1-5-32-548": "Account Operators",
		"S-1-5-32-549": "Server Operators",
		"S-1-5-32-550": "Print Operators",
		"S-1-5-32-551": "Backup Operators",
		"S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
	}
}

func (c *Client) SearchEnrollmentServices() ([]models.EnrollmentServiceRecord, error) {
	base := "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + c.cfg.BaseDN
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName"},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.EnrollmentServiceRecord, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, models.EnrollmentServiceRecord{
			Name:        e.GetAttributeValue("cn"),
			DNSHostName: e.GetAttributeValue("dNSHostName"),
		})
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (c *Client) SearchServiceAccountEntries() ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))",
		[]string{
			"cn",
			"displayName",
			"distinguishedName",
			"objectClass",
			"sAMAccountName",
			"servicePrincipalName",
			"memberOf",
			"userAccountControl",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	return res.Entries, nil
}

func (c *Client) SearchAdminSDHolderEntries() ([]*ldap.Entry, error) {
	ctrl := &ControlMicrosoftSDFlags{Flags: 0x04}
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(|(objectClass=user)(objectClass=group)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))(adminCount=1))",
		[]string{
			"cn",
			"displayName",
			"distinguishedName",
			"objectClass",
			"sAMAccountName",
			"memberOf",
			"nTSecurityDescriptor",
		},
		[]ldap.Control{ctrl},
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	return res.Entries, nil
}

func (c *Client) SearchDCComputerEntries() ([]*ldap.Entry, error) {
	base := "OU=Domain Controllers," + c.cfg.BaseDN
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=computer)",
		[]string{
			"name",
			"dNSHostName",
			"distinguishedName",
			"operatingSystem",
			"servicePrincipalName",
			"userAccountControl",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	return res.Entries, nil
}

func (c *Client) SearchGPOMap() (map[string]models.GPORecord, error) {
	gpos, err := c.SearchGPOs()
	if err != nil {
		return nil, err
	}
	out := make(map[string]models.GPORecord, len(gpos))
	for _, g := range gpos {
		out[strings.ToLower(g.DN)] = g
	}
	return out, nil
}

func (c *Client) GetEntryByDN(dn string, attrs []string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attrs,
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	return res.Entries[0], nil
}

func addADIDNSMapping(m map[string][]string, key, ip string) {
	key = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(key, ".")))
	ip = strings.TrimSpace(ip)

	if key == "" || net.ParseIP(ip) == nil {
		return
	}

	for _, existing := range m[key] {
		if existing == ip {
			return
		}
	}

	m[key] = append(m[key], ip)
}

func parseADIDNSARecord(raw []byte) (string, bool) {
	// AD-integrated DNS stores dnsRecord as a serialized DNS_RECORD structure.
	// Relevant header layout:
	// 0-1   DataLength
	// 2-3   Type
	// 4     Version
	// 5     Rank
	// 6-7   Flags
	// 8-11  Serial
	// 12-15 TTL
	// 16-19 Reserved
	// 20-23 Timestamp
	// 24..  Record data
	if len(raw) < 28 {
		return "", false
	}

	dataLen := int(binary.LittleEndian.Uint16(raw[0:2]))
	recordType := binary.LittleEndian.Uint16(raw[2:4])

	// A record
	if recordType != 0x0001 {
		return "", false
	}

	if dataLen != 4 {
		return "", false
	}

	if len(raw) < 24+dataLen {
		return "", false
	}

	ip := net.IP(raw[24 : 24+4]).To4()
	if ip == nil {
		return "", false
	}

	return ip.String(), true
}

func dnsNodeFQDNFromDN(dn string) string {
	if strings.TrimSpace(dn) == "" {
		return ""
	}

	parts := strings.Split(dn, ",")
	labels := make([]string, 0)

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Stop once we reach the MicrosoftDNS container.
		if strings.EqualFold(part, "CN=MicrosoftDNS") {
			break
		}

		if len(part) >= 3 && strings.EqualFold(part[:3], "DC=") {
			value := strings.TrimSpace(part[3:])
			if value != "" {
				labels = append(labels, value)
			}
		}
	}

	if len(labels) == 0 {
		return ""
	}

	return strings.ToLower(strings.Join(labels, "."))
}

func fileTimeToTime(v int64) time.Time {
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

func (c *Client) SearchPrivilegedGroupEntries() ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)(cn=Account Operators)(cn=Server Operators)(cn=Backup Operators))",
		[]string{
			"cn",
			"distinguishedName",
			"member",
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	return res.Entries, nil
}
