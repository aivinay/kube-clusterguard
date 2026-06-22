# Reproducibility

Kube ClusterGuard's checks are designed to be reproducible from a clean checkout
without cluster access.

## Recommended Python

- Python 3.10
- Python 3.11
- Python 3.12

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Equivalent repo command:

```bash
make install
```

## Validation

```bash
python -m unittest discover -s tests
ruff check .
python -m build
clusterguard doctor --manifest examples/risky-deployment.yaml
clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none
```

## CI Scope

GitHub Actions runs tests, linting, package build checks, and CLI smoke checks on
Python 3.10, 3.11, and 3.12.

## Release Artifacts

Tag builds and manual workflow runs build the source distribution and wheel,
validate them with `twine check`, and upload the distribution files as workflow
artifacts.
