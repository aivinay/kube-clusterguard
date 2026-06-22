# Release Checklist

Use this checklist before publishing a new GitHub release.

## Local Checks

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests
ruff check .
python -m build
clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none
clusterguard scan examples/clean-deployment.yaml --fail-on low
```

## Repository Hygiene

- README installation and scan examples work from a clean virtual environment.
- `CHANGELOG.md` includes user-visible changes.
- `docs/rules.md` matches the rule catalog.
- No secrets, local paths, or private environment values are present.
- CI is passing on the supported Python versions.
