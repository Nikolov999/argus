package ldapclient

import (
	"adreview/internal/models"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

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
		},
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	out := make([]models.CertTemplate, 0, len(res.Entries))
	for _, e := range res.Entries {
		enroll, _ := strconv.Atoi(e.GetAttributeValue("msPKI-Enrollment-Flag"))
		nameFlag, _ := strconv.Atoi(e.GetAttributeValue("msPKI-Certificate-Name-Flag"))
		out = append(out, models.CertTemplate{
			Name:           e.GetAttributeValue("cn"),
			DisplayName:    e.GetAttributeValue("displayName"),
			EKUs:           e.GetAttributeValues("pKIExtendedKeyUsage"),
			EnrollmentFlag: enroll,
			NameFlag:       nameFlag,
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
