# ADR-004 — PostgreSQL Research Backend

## Status

ACCEPTED

## Decision

CAPSTONE-1 uses PostgreSQL for persistent sanitized observations.

## Purpose

PostgreSQL is the persistent research/evidence layer.

Logical path:

```text
BROWSER
   ↓
SERVICE WORKER
   ↓
FASTAPI
   ↓
DATABASE LAYER
   ↓
POSTGRESQL
```

## Stored Information

The observations table stores sanitized metadata such as:

- observation identifier
- collection identifier
- domain
- sanitized URL
- HTTPS state
- form count
- input count
- script count
- requested data categories
- threat level
- model score
- policy action
- observation timestamp

## Not Stored

Raw:

- passwords
- OTPs
- CVVs
- form values
- request bodies
- authentication tokens

## Why PostgreSQL

PostgreSQL supports:

- structured relational storage
- reproducible research queries
- indexed observations
- schema constraints
- future analytics
- backend integration

## Consequences

### Positive

- reliable persistence
- queryable evidence
- reproducible experiments
- clear relational structure

### Negative

- additional runtime dependency
- credential management
- schema migration requirements

## Security Requirement

Database credentials remain local-only and must not be committed to Git.