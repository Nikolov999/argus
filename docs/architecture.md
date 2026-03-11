# ADReview Architecture

## Overview

ADReview is a modular, read-only Active Directory assessment framework built in Go. It separates collection, modeling, analysis, reporting, and presentation into distinct layers to keep the codebase maintainable and extensible.

---

## Pipeline

```text
LDAP collectors
      ↓
data models
      ↓
audit modules
      ↓
report engine
      ↓
CLI interface

---

### Layer breakdown
## LDAP collectors

The LDAP layer is responsible for connecting to the domain controller and retrieving directory data for supported object classes and containers.

Examples:

- users

- groups

- computers

- GPO containers

- trusted domains

- certificate templates

- rollment services

This layer is intentionally read-only.

##  Data models

The models layer defines normalized structures used across the tool.

Examples:

- UserRecord

- GroupRecord

- ComputerRecord

- TrustRecord

- GPORecord

- CertTemplate

This keeps collectors and audit logic decoupled.

## Audit modules

Each module evaluates collected data for one review objective.

Examples:

- kerb

- delegaudit

- gpoenum

- tierzero

- sprawl

This makes the tool easy to extend without coupling all logic into one path.

## Report engine

The report layer formats structured results for:

JSON export

HTML export

This allows the same findings to be shown both in the terminal and in shareable artifacts.

## CLI interface

The CLI layer:

- parses flags

- validates required inputs

- routes execution to modules

- prints readable terminal output

- triggers optional report generation

### Design principles
- Read-only review

ADReview is intended for defensive assessment and documentation. It does not modify directory objects or perform exploit workflows.

### Clear module boundaries

Each module has a narrowly defined purpose. This improves maintainability and makes the repository easier to explain in a portfolio.

### Operator-friendly output

The CLI output is structured to support both quick operator use and screenshot-based portfolio presentation.

### Enterprise relevance

The selected modules focus on real enterprise review areas:

- Kerberos hygiene

- delegation posture

- GPO consistency

- privileged scope

- Tier 0 inventory

- privilege sprawl

- SMB and remote management exposure

### Why this structure matters

This project is not just a script collection. It is a framework with:

- layered architecture

- reusable data models

- modular analysis paths

- reporting support

- defensive security orientation
