# Contributing

## Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
python examples/run_demo.py
```

## Invariants

Changes must preserve:

- fail-closed behavior for a missing baseline by default;
- case-level failure even when aggregate thresholds are lowered;
- independent treatment of uncertain, skipped, and execution-error outcomes;
- exit code `2` only for invalid inputs/configuration;
- output containing no unescaped user data in HTML;
- no execution of the agent or external services from the gate.

## Report fixtures

When changing the report contract, update:

- `examples/build_reports.py`
- `examples/reports/*.json`
- `tests/` coverage
- `README.md` and the Chinese design note

## Security reports

See [`SECURITY.md`](SECURITY.md).
