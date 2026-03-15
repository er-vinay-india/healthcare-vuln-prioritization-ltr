# Ranking Logic

This document explains how the project prioritizes CVEs at a high level.

## Core Idea

The ranking does not treat healthcare relevance as the only signal.
It prioritizes CVEs using a combination of:

- active exploitation evidence
- exploit likelihood
- severity
- recency
- healthcare context
- attacker-behavior context

## Priority Order

In simple terms, the ranking logic is:

1. Exploited or likely-to-be-exploited CVEs first
2. Severe CVEs next
3. Healthcare-specific context as an additional boost

This means a non-healthcare CVE can still rank above a healthcare CVE if the non-healthcare CVE is actively exploited and clearly more dangerous in practice.

## Main Signals

- `kev_flag` for known exploited vulnerabilities
- `epss_score` for exploitation probability
- `cvss` for severity
- recency-related features
- healthcare-specific flags
- ATT&CK and CHPL-derived signals

## How To Read The Ranking

- Top results should be treated as immediate review candidates.
- Healthcare context helps refine ranking, but it does not override strong exploitation evidence.
- Lower-ranked results are still useful, but usually less urgent.

## If You Want Different Behavior

If your use case requires healthcare-only prioritization, the ranking strategy can be adjusted by:

- increasing healthcare-related weights
- filtering to healthcare-relevant CVEs before ranking
- changing how interaction features are used

## Related Docs

- `ARCHITECTURE.md` for system structure
- `QUICKSTART.md` for first use
- `DOCKER_GUIDE.md` for containerized runs
