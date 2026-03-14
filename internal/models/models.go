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
	AdminNameRegex string
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
	Name               string   `json:"name"`
	DisplayName        string   `json:"displayName"`
	EKUs               []string `json:"ekus,omitempty"`
	EnrollmentFlag     int      `json:"enrollmentFlag"`
	NameFlag           int      `json:"nameFlag"`
	RASignatureCount   int      `json:"raSignatureCount,omitempty"`
	SchemaVersion      int      `json:"schemaVersion,omitempty"`
	SecurityDescriptor []byte   `json:"-"`
}

type CertFinding struct {
	Name                   string   `json:"name"`
	DisplayName            string   `json:"displayName"`
	EKUs                   []string `json:"ekus,omitempty"`
	EnrollmentFlag         int      `json:"enrollmentFlag,omitempty"`
	NameFlag               int      `json:"nameFlag,omitempty"`
	RASignatureCount       int      `json:"raSignatureCount,omitempty"`
	SchemaVersion          int      `json:"schemaVersion,omitempty"`
	EnrollPrincipals       []string `json:"enrollPrincipals,omitempty"`
	AutoEnrollPrincipals   []string `json:"autoEnrollPrincipals,omitempty"`
	DangerousACLPrincipals []string `json:"dangerousAclPrincipals,omitempty"`
	Labels                 []string `json:"labels,omitempty"`
	RiskScore              int      `json:"riskScore,omitempty"`
	RiskSummary            string   `json:"riskSummary"`
	Notes                  []string `json:"notes,omitempty"`
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

type ACLExposureTarget struct {
	Name               string   `json:"name"`
	DN                 string   `json:"distinguishedName"`
	ObjectType         string   `json:"objectType"`
	ObjectClass        []string `json:"objectClass,omitempty"`
	SecurityDescriptor []byte   `json:"-"`
}

type ACLExposureFinding struct {
	Object         string   `json:"object"`
	ObjectType     string   `json:"objectType"`
	DN             string   `json:"distinguishedName"`
	Principal      string   `json:"principal"`
	PrincipalSID   string   `json:"principalSid,omitempty"`
	Right          string   `json:"right"`
	Severity       Severity `json:"severity"`
	Reason         string   `json:"reason"`
	Inherited      bool     `json:"inherited"`
	ObjectTypeGUID string   `json:"objectTypeGuid,omitempty"`
}

type ACLExposureResult struct {
	Findings []ACLExposureFinding `json:"findings"`
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

type Account struct {
	Name    string `json:"name"`
	UPN     string `json:"upn,omitempty"`
	DN      string `json:"distinguishedName"`
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind"`
}

type NestedGroup struct {
	Name string `json:"name"`
	DN   string `json:"distinguishedName"`
	Path string `json:"path"`
}

type PrivilegedGroup struct {
	Name              string        `json:"name"`
	DN                string        `json:"distinguishedName"`
	DirectMemberCount int           `json:"directMemberCount"`
	NestedGroups      []NestedGroup `json:"nestedGroups,omitempty"`
	PrivilegedUsers   []Account     `json:"privilegedUsers,omitempty"`
	ServiceAccounts   []Account     `json:"serviceAccounts,omitempty"`
	ReviewCandidates  []Account     `json:"reviewCandidates,omitempty"`
}

type PrivMapResult struct {
	Domain             string            `json:"domain"`
	AdminNameRegexUsed string            `json:"adminNameRegexUsed"`
	Groups             []PrivilegedGroup `json:"groups"`
	TotalPrivGroups    int               `json:"totalPrivGroups"`
	TotalUsers         int               `json:"totalUsers"`
	TotalNestedGroups  int               `json:"totalNestedGroups"`
	TotalServiceAccts  int               `json:"totalServiceAccts"`
	TotalReviewUsers   int               `json:"totalReviewUsers"`
}

type BlastIdentitySummary struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	DN                   string   `json:"distinguishedName"`
	PrivilegedGroupCount int      `json:"privilegedGroupCount"`
	PrivilegedGroups     []string `json:"privilegedGroups,omitempty"`
	ServiceHostCount     int      `json:"serviceHostCount,omitempty"`
	ServiceHosts         []string `json:"serviceHosts,omitempty"`
	ControlScore         int      `json:"controlScore"`
	Reason               string   `json:"reason"`
}

type BlastGroupSummary struct {
	Name                string   `json:"name"`
	DN                  string   `json:"distinguishedName"`
	DirectMemberCount   int      `json:"directMemberCount"`
	NestedGroupCount    int      `json:"nestedGroupCount"`
	UserCount           int      `json:"userCount"`
	ServiceAccountCount int      `json:"serviceAccountCount"`
	ConcentrationScore  int      `json:"concentrationScore"`
	KeyPaths            []string `json:"keyPaths,omitempty"`
}

type BlastHostSummary struct {
	Host                   string   `json:"host"`
	DN                     string   `json:"distinguishedName"`
	Role                   string   `json:"role"`
	PrivilegedIdentityRefs []string `json:"privilegedIdentityRefs,omitempty"`
	ServiceAccounts        []string `json:"serviceAccounts,omitempty"`
	AggregationScore       int      `json:"aggregationScore"`
	Reason                 string   `json:"reason"`
}

type BlastResult struct {
	TopIdentitySpread       []BlastIdentitySummary `json:"topIdentitySpread"`
	TopGroupConcentration   []BlastGroupSummary    `json:"topGroupConcentration"`
	PrivilegeAggregationTop []BlastHostSummary     `json:"privilegeAggregationTop"`
}

type AdminSDObject struct {
	Name                 string   `json:"name"`
	ObjectType           string   `json:"objectType"`
	DN                   string   `json:"distinguishedName"`
	AdminCount           int      `json:"adminCount"`
	CurrentlyPrivileged  bool     `json:"currentlyPrivileged"`
	PrivilegeReasons     []string `json:"privilegeReasons,omitempty"`
	InheritanceDisabled  bool     `json:"inheritanceDisabled"`
	PersistenceIndicator string   `json:"persistenceIndicator"`
}

type AdminSDResult struct {
	ProtectedObjects           []AdminSDObject `json:"protectedObjects"`
	NoCurrentReason            []AdminSDObject `json:"noCurrentReason"`
	InheritanceDisabledDrift   []AdminSDObject `json:"inheritanceDisabledDrift"`
	StaleProtectedObjects      []AdminSDObject `json:"staleProtectedObjects"`
	PersistentACLReviewObjects []AdminSDObject `json:"persistentAclReviewObjects"`
}

type ServiceImpactAccount struct {
	Name                   string   `json:"name"`
	DN                     string   `json:"distinguishedName"`
	Kind                   string   `json:"kind"`
	Privileged             bool     `json:"privileged"`
	PrivilegeReasons       []string `json:"privilegeReasons,omitempty"`
	HostCount              int      `json:"hostCount"`
	Hosts                  []string `json:"hosts,omitempty"`
	SPNs                   []string `json:"spns,omitempty"`
	SingleCompromiseImpact string   `json:"singleCompromiseImpact"`
}

type ServiceImpactResult struct {
	Accounts                    []ServiceImpactAccount `json:"accounts"`
	PrivilegedSPNAccounts       []ServiceImpactAccount `json:"privilegedSpnAccounts"`
	BroadReuseAccounts          []ServiceImpactAccount `json:"broadReuseAccounts"`
	AdminServiceOverlapAccounts []ServiceImpactAccount `json:"adminServiceOverlapAccounts"`
}

type DCAttackSurfaceIdentity struct {
	Name   string   `json:"name"`
	DN     string   `json:"distinguishedName"`
	Groups []string `json:"groups,omitempty"`
}

type DCAttackSurfaceAccount struct {
	Name    string   `json:"name"`
	DN      string   `json:"distinguishedName"`
	Hosts   []string `json:"hosts,omitempty"`
	SPNs    []string `json:"spns,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

type DCAttackSurfaceHost struct {
	Host              string   `json:"host"`
	DN                string   `json:"distinguishedName"`
	Protocols         []string `json:"protocols,omitempty"`
	ServiceAccounts   []string `json:"serviceAccounts,omitempty"`
	DelegationSignals []string `json:"delegationSignals,omitempty"`
}

type DCAttackSurfaceGPO struct {
	Name    string `json:"name"`
	GUID    string `json:"guid,omitempty"`
	Path    string `json:"path,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type DCAttackSurfaceResult struct {
	WhoCanLogOnToDCs          []DCAttackSurfaceIdentity `json:"whoCanLogOnToDcs"`
	NonstandardAccountsOnDCs  []DCAttackSurfaceAccount  `json:"nonstandardAccountsOnDcs"`
	ProtocolExposure          []DCAttackSurfaceHost     `json:"protocolExposure"`
	GPOsAffectingDCOU         []DCAttackSurfaceGPO      `json:"gposAffectingDcOu"`
	DelegationAndGroupAnomaly []DCAttackSurfaceHost     `json:"delegationAndGroupAnomaly"`
	CollectionNotes           []string                  `json:"collectionNotes,omitempty"`
}
