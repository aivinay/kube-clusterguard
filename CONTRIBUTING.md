# Contributing

Thank you for considering a contribution to Kube ClusterGuard.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests
ruff check .
```

## Contribution guidelines

- Keep new rules deterministic and explainable.
- Include tests for every new rule or report format.
- Prefer small, auditable policy checks over broad opaque scoring.
- Update `README.md` and `docs/roadmap.md` when behavior changes.
