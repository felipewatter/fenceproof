.PHONY: test check smoke compile
PYTHON ?= python3
export PYTHONPATH := src

test:
	$(PYTHON) -m unittest discover -s tests -v

compile:
	$(PYTHON) -m compileall -q src tests

check: compile test smoke

smoke:
	$(PYTHON) -m fenceproof check --policy examples/secure-policy.json --fail-on low
	$(PYTHON) -m fenceproof diff --before examples/secure-policy.json --after examples/risky-policy.json --format json > /dev/null
