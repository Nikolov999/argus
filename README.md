# ARGUS

**Active Directory Review Framework**  
**Author:** Bobo Nikolov, EchoPentest

---

## Quick Install 

### Install for Linux

- wget https://github.com/Nikolov999/argus/dist/v2.0.0/argus_linux_amd64

- chmod +x argus_linux_amd64

- sudo mv adreview_linux_amd64 /usr/local/bin/adreview

- argus --help

- argus_linux_amd64 256 hash - 656b314027d1b874ec395005c55f57d926cd7037aa0190f8f57e9c2fce558d10


### Install for Windows

Download `argus_windows_amd64.zip`.

Run from PowerShell:


argus_windows_amd64.exe kerb -d corp.local -dc 10.10.10.5

argus_windows_amd64.zip 256 hash - dd1656b200214c71ab6445bb5372b013d104770733209f560fd672fcc65a21a7


### Install for MacOS


Download the correct binary for your architecture:

Intel:
- argus_darwin_amd64

argus_darwin_amd64 256 hash - dbf99d89259e2e18146cc738fc1cc357755ef9814ada8687b7bc41b7f330b56a 

Apple Silicon:
- argus_darwin_arm64

argus_darwin_arm64 256 hash - e8c6a707b3b72117104d0a33feea9a734dc02a6bef4241dd3ee84c9485e31fdc

Make executable:
chmod +x argus_darwin_arm64

Run:
./argus_darwin_arm64 --help

---

ARGUS is a modular, read-only Active Directory security assessment toolkit written in Go. It is designed for configuration auditing, exposure review, and defensive reporting in enterprise environments.

## Why this project exists

Active Directory environments accumulate configuration drift, privilege sprawl, legacy Kerberos settings, unmanaged delegation, inconsistent GPOs, and broad administrative exposure. ARGUS was built to provide a fast, operator-friendly CLI for reviewing those conditions through a structured, extensible framework.

---

## Core design goals

- Read-only assessment
- Enterprise-friendly CLI output
- Clear module separation
- JSON and HTML reporting
- Modular architecture for future expansion
- Defensive review only

---

## Features

- Kerberos exposure analysis
- Delegation auditing
- AD CS certificate surface review
- Privileged group scope analysis
- GPO enumeration
- Domain trust analysis
- Remote management surface discovery
- SMB exposure review
- ACL delegation indicators
- Tier 0 inventory
- Privilege sprawl review
- JSON / HTML reporting

---

## Modules

| Module | Description |
|---|---|
| `enum` | Domain inventory counts |
| `kerb` | Kerberos exposure review |
| `misconfig` | Configuration hygiene findings |
| `adcs` | AD CS summary |
| `gpoenum` | Group Policy Object inventory |
| `trustaudit` | Domain trust inventory |
| `delegaudit` | Delegation review |
| `certsurface` | Certificate template surface review |
| `adminscope` | Privileged group scope review |
| `lateralmap` | Remote administration surface inventory |
| `shareaudit` | SMB exposure inventory |
| `aclaudit` | Delegation and protected-object ACL indicators |
| `tierzero` | Tier 0 asset and identity inventory |
| `sprawl` | Privilege sprawl review |
| `auto` | Combined core assessment |

---

## Example

```bash
argus auto -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!'
Example output
Active Directory Review Framework
by EchoPentest

ARGUS EXECUTIVE SUMMARY

Users: 1532
Groups: 221
Computers: 412
Pre-auth disabled: 2
SPN accounts: 31
Privileged SPN accounts: 1
Legacy encryption review items: 6
Misconfiguration findings: 4
AD CS templates reviewed: 3
```

---

## Installation

### Build locally
go build -o argus ./cmd/argus

### Install globally
sudo cp argus /usr/local/bin/argus
sudo chmod +x /usr/local/bin/argus
hash -r

---

## Usage

### Inventory
argus enum -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!'

### Kerberos review
argus kerb -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!' --password-age

### GPO review
argus gpoenum -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!'

### Tier 0 inventory
argus tierzero -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!'

### Privilege sprawl review
argus sprawl -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!'

### Reporting
argus kerb -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!' --json kerb.json
argus auto -d corp.local -dc 10.10.10.5 -u 'CORP\auditor' -p 'Password123!' --html review.html

### Reporting outputs

- Human-readable CLI output

- JSON artifact for automation

- HTML report for review and sharing

### HTML Reporting

Each module can export structured HTML reports suitable for documentation or client reporting.

Example:

```bash
argus kerb -d corp.local -dc 10.10.10.5 --html kerberos_report.html
```

---

## Architecture summary

LDAP collectors
      ↓
data models
      ↓
audit modules
      ↓
report engine
      ↓
CLI interface

More detail is available in docs/architecture.md.

---

## Safe scope

ARGUS is designed for defensive assessment and reporting. It does not perform:

- credential extraction

- ticket requests for cracking

- exploit generation

- attack-path generation

- abuse command generation

- privilege escalation workflows

### Repository layout
argus/
├── cmd/
├── internal/
├── docs/
├── examples/
├── .github/workflows/
├── go.mod
├── README.md
├── LICENSE
└── CHANGELOG.md
### What this project demonstrates

- Go development

- Active Directory internals

- LDAP collection patterns

- network exposure review

- modular CLI architecture

- reporting design

- security engineering mindset

---

## Screenshots

### Kerberos Security Review

![Kerberos CLI](docs/screenshots/kerb.png)

### Kerberos HTML Report

![Kerberos HTML Report](docs/screenshots/kerb-html-report.png)

## Privilege Sprawl Review

![Sprawl](screenshots/sprawl.png)

### Lateral Mapping

![Auto Summary](docs/screenshots/lateralmap.png)


---

## Author

Bobo Nikolov, EchoPentest
