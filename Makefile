# GNAT Makefile
.DEFAULT_GOAL := help
PYTHON  ?= python
PIP     ?= pip
PYTEST  ?= pytest
RUFF    ?= ruff
MYPY    ?= mypy
SRC     := gnat
TESTS   := tests

.PHONY: help install test coverage integration lint fmt typecheck check build clean docs codegen build-rust build-rust-dev docker-build docker-up docker-search docker-full docker-down docker-logs test-docker test-docker-up test-docker-down

help:
	@echo ""
	@echo "GNAT development targets"
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
	@echo "  make build-rust    Build + install the Rust native extension (release)"
	@echo "  make build-rust-dev  Build Rust extension in dev mode (faster, no optimisations)"
	@echo "  make docker-build  Build all Docker service images"
	@echo "  make docker-up     Start core services (detached)"
	@echo "  make docker-search Start core + Solr search sidecar"
	@echo "  make docker-full   Start all services including Grafana"
	@echo "  make docker-down   Stop all services"
	@echo "  make docker-logs   Tail logs for all services"
	@echo "  make test-docker-up    Start test containers (ES + Solr)"
	@echo "  make test-docker-down  Stop and remove test containers"
	@echo "  make test-docker       Run Docker integration test suite"
	@echo ""

build-rust:
	cd rust_core && maturin build --release
	$(PIP) install rust_core/target/wheels/gnat_core-*.whl --force-reinstall

build-rust-dev:
	cd rust_core && maturin develop

install:
	$(PIP) install -e ".[dev]" httpx

test:
	$(PYTEST) $(TESTS)/unit/ -v --tb=short

coverage:
	$(PYTEST) $(TESTS)/unit/ \
	    --cov=$(SRC) --cov-report=term-missing --cov-report=html:htmlcov --tb=short
	@echo "Coverage report: htmlcov/index.html"

integration:
	@[ -n "$(GNAT_CONFIG)" ] || (echo "ERROR: set GNAT_CONFIG=/path/to/real.ini"; exit 1)
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

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-search:
	docker compose --profile search up -d

docker-full:
	docker compose --profile full up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

DOCKER_TEST_COMPOSE := docker/test/docker-compose.test.yml

test-docker-up:
	docker compose -f $(DOCKER_TEST_COMPOSE) up -d --pull missing

test-docker-down:
	docker compose -f $(DOCKER_TEST_COMPOSE) down -v

test-docker: test-docker-up
	$(PYTEST) $(TESTS)/integration/ --run-docker -v --tb=short ; \
	$(MAKE) test-docker-down
