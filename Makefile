PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_RUFF := $(VENV)/bin/ruff

.PHONY: install test lint build smoke check docker clean

install:
	$(PYTHON) -m venv --clear $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -e ".[dev]"

test:
	PYTHONPATH=src $(VENV_PYTHON) -m unittest discover -s tests

lint:
	$(VENV_RUFF) check .

build:
	$(VENV_PYTHON) -m build

smoke:
	PYTHONPATH=src $(VENV_PYTHON) -m clusterguard.cli --version
	PYTHONPATH=src $(VENV_PYTHON) -m clusterguard.cli doctor --manifest examples/risky-deployment.yaml
	PYTHONPATH=src $(VENV_PYTHON) -m clusterguard.cli rules --format markdown
	PYTHONPATH=src $(VENV_PYTHON) -m clusterguard.cli scan examples/risky-deployment.yaml --format markdown --fail-on none

check: lint test build smoke

docker:
	docker build -t kube-clusterguard:dev .

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
