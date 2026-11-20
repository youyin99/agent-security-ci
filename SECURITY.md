# Security Policy

## Scope

Agent Security CI compares report artifacts and enforces a release policy. It does
not execute the evaluated agent or access external services. Its security value
depends on the baseline being approved from a trusted workflow.

## Reporting

Use a private GitHub Security Advisory for this repository.

Include:

- affected version/commit;
- a report/config pair that bypasses or incorrectly fails the gate;
- expected and observed exit codes;
- whether the issue could let a security regression pass.

## In scope

- gate bypass caused by malformed or missing data;
- a weak or skipped case incorrectly passing;
- baseline regression undetected;
- command injection in the composite action;
- HTML/report injection;
- exit code inconsistency.

## Out of scope

- trusting a baseline that was itself generated from the current branch;
- AgentProbe evidence forgery by an actor who can modify reports;
- GitHub Actions platform compromise;
- vulnerabilities in unrelated CI systems.
