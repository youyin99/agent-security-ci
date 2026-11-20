# Agent Security Gate Action

```yaml
- uses: youyin99/agent-security-ci/action@v1
  with:
    baseline: .security/agentprobe-baseline.json
    current: reports/agentprobe-report.json
    config: .security/gate-policy.json
    out: reports/gate
```

The action installs this repository from the action path, runs the offline gate,
emits GitHub error annotations for failed cases and checks, and writes:

- `gate-report.json`
- `gate-report.html`

Exit code `1` fails the job. Missing or malformed inputs fail closed. The action
does not run the agent or access external services.

## Baseline integrity

The baseline should be an approved, reviewed report. Do not generate it in the
same pull-request job, because doing so would make the current behavior its own
baseline. The workflow template in `../templates/agent-security-gate.yml` shows
the intended separation.
