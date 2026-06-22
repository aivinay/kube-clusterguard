.PHONY: install test lint build smoke clean

install:
	python -m pip install -e ".[dev]"

test:
	python -m unittest discover -s tests

lint:
	ruff check .

build:
	python -m build

smoke:
	clusterguard --version
	clusterguard rules --format markdown
	clusterguard scan examples/risky-deployment.yaml --format markdown --fail-on none

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
