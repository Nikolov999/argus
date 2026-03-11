# ADReview Modules

## enum
Domain-wide inventory counts for users, groups, and computers.

## kerb
Reviews Kerberos-related exposure conditions such as:
- pre-authentication disabled
- SPN-bearing accounts
- privileged accounts with SPNs
- legacy encryption settings
- optional password age review

## misconfig
Provides summary-level hygiene findings from the current data scope.

## adcs
Provides a safe, read-only summary of certificate template posture.

## gpoenum
Enumerates Group Policy Objects and highlights basic consistency issues.

## trustaudit
Inventories domain trust relationships and summarizes trust direction and type.

## delegaudit
Reviews delegation configuration including:
- unconstrained delegation
- constrained delegation
- resource-based constrained delegation indicators

## certsurface
Summarizes certificate template exposure indicators and EKU posture.

## adminscope
Reviews privileged group scope and direct membership.

## lateralmap
Maps remote administration surface based on reachable management services such as:
- RPC
- SMB
- RDP
- WinRM

## shareaudit
Reviews SMB reachability and flags domain controller share exposure context.

## aclaudit
Provides read-only delegated-control indicators using available directory metadata such as:
- managedBy delegation indicators
- protected object status

## tierzero
Builds a Tier 0 inventory including:
- domain controllers
- privileged groups
- privileged users
- PKI servers
- critical service accounts
- admin workstation candidates

## sprawl
Highlights identity hygiene issues including:
- broad privileged membership
- nested privileged grouping
- redundant privileged assignments

## auto
Runs the core assessment path and summarizes the environment.
