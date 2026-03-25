# CTM-SAK Makefile
.DEFAULT_GOAL := help
PYTHON  ?= python
PIP     ?= pip
PYTEST  ?= pytest
RUFF    ?= ruff
MYPY    ?= mypy
SRC     := ctm_sak
TESTS   := tests

.PHONY: help install test coverage integration lint fmt typecheck check build clean docs codegen

help:
	@echo ""
	@echo "CTM-SAK development targets"
	@echo "────────────────────────────────────────────"
	@echo "  make install       Install package + all dev deps"
	@echo "  make test          Run all unit tests"
	@echo "  make coverage      Run tests with HTML coverage report"
	@echo "  make integration   Run live API integration tests"
	@echo "  make lint          Lint with ruff (check + format check)"
	@echo "  make fmt           Auto-format with ruff"
	@echo "  make typecheck     Type-check with mypy"
	@echo "  make check         lint + typecheck"
	@echo "  make docs          Build Sphinx HTML documentation"
	@echo "  make build         Build sdist + wheel"
	@echo "  make clean         Remove all build artifacts"
	@echo ""

install:
	$(PIP) install -e ".[dev]" httpx

test:
	$(PYTEST) $(TESTS)/unit/ -v --tb=short

coverage:
	$(PYTEST) $(TESTS)/unit/ \
	    --cov=$(SRC) --cov-report=term-missing --cov-report=html:htmlcov --tb=short
	@echo "Coverage report: htmlcov/index.html"

integration:
	@[ -n "$(CTM_SAK_CONFIG)" ] || (echo "ERROR: set CTM_SAK_CONFIG=/path/to/real.ini"; exit 1)
	$(PYTEST) $(TESTS)/integration/ --run-integration -v

lint:
	$(RUFF) check $(SRC) $(TESTS)
	$(RUFF) format --check $(SRC) $(TESTS)

fmt:
	$(RUFF) format $(SRC) $(TESTS)
	$(RUFF) check --fix $(SRC) $(TESTS)

typecheck:
	$(MYPY) $(SRC) --ignore-missing-imports

check: lint typecheck

docs:
	cd docs && make html

build: clean
	$(PYTHON) -m build

clean:
	rm -rf build dist *.egg-info htmlcov .coverage .mypy_cache .ruff_cache docs/build
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
