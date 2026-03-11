package models

import "time"

type Config struct {
	Domain         string
	DC             string
	BaseDN         string
	LDAPURL        string
	Username       string
	Password       string
	UseLDAPS       bool
	PrivilegedOnly bool
	PasswordAge    bool
	JSONOut        string
	HTMLOut        string
	TimeoutSeconds int
	Workers        int
}

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type UserRecord struct {
	SAMAccountName       string    `json:"samAccountName"`
	DistinguishedName    string    `json:"distinguishedName"`
	ServicePrincipalName []string  `json:"servicePrincipalName"`
	UserAccountControl   int       `json:"userAccountControl"`
	MSEncryptionTypes    int       `json:"msDS-SupportedEncryptionTypes"`
	AdminCount           int       `json:"adminCount"`
	PwdLastSet           time.Time `json:"pwdLastSet,omitempty"`
	MemberOf             []string  `json:"memberOf,omitempty"`
}

type EnumSummary struct {
	Users     int `json:"users"`
	Groups    int `json:"groups"`
	Computers int `json:"computers"`
}

type KerberosFinding struct {
	SAMAccountName string   `json:"samAccountName"`
	DN             string   `json:"distinguishedName"`
	Reason         string   `json:"reason"`
	SPNs           []string `json:"spns,omitempty"`
}

type KerberosResult struct {
	PreAuthDisabled       []KerberosFinding `json:"preAuthDisabled"`
	SPNAccounts           []KerberosFinding `json:"spnAccounts"`
	PrivilegedSPNAccounts []KerberosFinding `json:"privilegedSpnAccounts"`
	LegacyEncryption      []KerberosFinding `json:"legacyEncryption"`
	PasswordAgeReview     []KerberosFinding `json:"passwordAgeReview,omitempty"`
}

type MisconfigFinding struct {
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

type MisconfigResult struct {
	Findings []MisconfigFinding `json:"findings"`
}

type ADCSTemplate struct {
	Name        string   `json:"name"`
	Flags       []string `json:"flags"`
	RiskSummary string   `json:"riskSummary"`
}

type ADCSResult struct {
	Templates []ADCSTemplate `json:"templates"`
}

type GPORecord struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	DN          string `json:"distinguishedName"`
	FileSysPath string `json:"fileSysPath"`
	Version     string `json:"version"`
	WhenChanged string `json:"whenChanged"`
	Flags       string `json:"flags"`
}

type GPOFinding struct {
	Name        string   `json:"name"`
	GUID        string   `json:"guid"`
	Path        string   `json:"path"`
	Version     string   `json:"version"`
	Changed     string   `json:"changed"`
	Flags       string   `json:"flags"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
}

type GPOResult struct {
	GPOs    []GPOFinding   `json:"gpos"`
	Summary map[string]int `json:"summary,omitempty"`
}

type TrustRecord struct {
	Partner   string `json:"partner"`
	Direction int    `json:"direction"`
	Type      int    `json:"type"`
	FlatName  string `json:"flatName"`
}

type TrustFinding struct {
	Partner   string `json:"partner"`
	FlatName  string `json:"flatName"`
	Direction string `json:"direction"`
	Type      string `json:"type"`
}

type TrustResult struct {
	Trusts []TrustFinding `json:"trusts"`
}

type DelegationPrincipal struct {
	SAMAccountName       string   `json:"samAccountName"`
	DN                   string   `json:"distinguishedName"`
	UAC                  int      `json:"userAccountControl"`
	AllowedToDelegateTo  []string `json:"allowedToDelegateTo,omitempty"`
	HasRBCDDescriptor    bool     `json:"hasRbcdDescriptor"`
	ServicePrincipalName []string `json:"servicePrincipalName,omitempty"`
}

type DelegationFinding struct {
	Principal string   `json:"principal"`
	DN        string   `json:"distinguishedName"`
	Reason    string   `json:"reason"`
	Targets   []string `json:"targets,omitempty"`
}

type DelegationResult struct {
	Unconstrained []DelegationFinding `json:"unconstrained"`
	Constrained   []DelegationFinding `json:"constrained"`
	ResourceBased []DelegationFinding `json:"resourceBased"`
}

type CertTemplate struct {
	Name           string   `json:"name"`
	DisplayName    string   `json:"displayName"`
	EKUs           []string `json:"ekus,omitempty"`
	EnrollmentFlag int      `json:"enrollmentFlag"`
	NameFlag       int      `json:"nameFlag"`
}

type CertFinding struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	EKUs        []string `json:"ekus,omitempty"`
	RiskSummary string   `json:"riskSummary"`
}

type CertResult struct {
	Templates []CertFinding `json:"templates"`
}

type GroupRecord struct {
	Name    string   `json:"name"`
	Members []string `json:"members,omitempty"`
}

type AdminGroup struct {
	Name        string   `json:"name"`
	MemberCount int      `json:"memberCount"`
	Members     []string `json:"members,omitempty"`
}

type AdminScopeResult struct {
	Groups []AdminGroup `json:"groups"`
}

type ComputerRecord struct {
	Name        string `json:"name"`
	DNSHostName string `json:"dnsHostName"`
	DN          string `json:"distinguishedName"`
	OS          string `json:"operatingSystem"`
}

type LateralService struct {
	Host     string   `json:"host"`
	Services []string `json:"services,omitempty"`
}

type LateralResult struct {
	Targets []LateralService `json:"targets"`
}

type ShareFinding struct {
	Host         string   `json:"host"`
	SMBReachable bool     `json:"smbReachable"`
	Notes        []string `json:"notes,omitempty"`
}

type ShareResult struct {
	Shares []ShareFinding `json:"shares"`
}

type ACLTargetRecord struct {
	ObjectType string `json:"objectType"`
	Name       string `json:"name"`
	DN         string `json:"distinguishedName"`
	ManagedBy  string `json:"managedBy,omitempty"`
	AdminCount int    `json:"adminCount,omitempty"`
}

type ACLFinding struct {
	Object      string   `json:"object"`
	ObjectType  string   `json:"objectType"`
	Principal   string   `json:"principal"`
	Right       string   `json:"right"`
	Severity    Severity `json:"severity"`
	Remediation string   `json:"remediation"`
	Note        string   `json:"note"`
}

type ACLAuditResult struct {
	Findings []ACLFinding `json:"findings"`
}

type EnrollmentServiceRecord struct {
	Name        string `json:"name"`
	DNSHostName string `json:"dnsHostName"`
}

type TierZeroAsset struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Detail   string `json:"detail,omitempty"`
}

type TierZeroResult struct {
	Assets []TierZeroAsset `json:"assets"`
}

type SprawlFinding struct {
	Category    string   `json:"category"`
	Object      string   `json:"object"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

type SprawlResult struct {
	Findings []SprawlFinding `json:"findings"`
}

type AutoResult struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	Config      Config          `json:"config"`
	Enum        EnumSummary     `json:"enum"`
	Kerberos    KerberosResult  `json:"kerberos"`
	Misconfig   MisconfigResult `json:"misconfig"`
	ADCS        ADCSResult      `json:"adcs"`
}

type ReportEnvelope struct {
	GeneratedAt time.Time   `json:"generatedAt"`
	Module      string      `json:"module"`
	Config      Config      `json:"config"`
	Data        interface{} `json:"data"`
}
