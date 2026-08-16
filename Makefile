PYTHON := .venv/bin/python
PYTEST := .venv/bin/pytest

.PHONY: help venv ingest build analyse data fixtures test lint app requirements clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

venv: ## create the environment and install pinned dependencies
	uv venv --python 3.12 .venv
	VIRTUAL_ENV=.venv uv pip install -r requirements-dev.txt

ingest: ## download the raw feeds into data/raw and write the manifest
	$(PYTHON) -m src.ingest

build: ## join the feeds into data/processed/vulnerabilities.parquet
	$(PYTHON) -m src.build

analyse: ## compute every published number into data/processed/analysis.json
	$(PYTHON) -m src.analyse

data: ingest build analyse ## the whole pipeline, from empty to artefacts

fixtures: ## regenerate the test fixtures from the raw feeds
	$(PYTHON) -m scripts.make_fixtures

test: ## run the test suite (no network access)
	$(PYTEST)

lint:
	VIRTUAL_ENV=.venv uvx ruff check src tests scripts

app: ## serve the dashboard locally
	.venv/bin/streamlit run app.py

requirements: ## regenerate the pins from the resolved environment
	@VIRTUAL_ENV=.venv uv pip freeze | grep -vE '^(pytest|pluggy|iniconfig)==' > requirements.txt
	@printf -- '-r requirements.txt\n' > requirements-dev.txt
	@VIRTUAL_ENV=.venv uv pip freeze | grep -E '^(pytest|pluggy|iniconfig)==' >> requirements-dev.txt
	@echo "requirements.txt and requirements-dev.txt regenerated"

clean: ## remove generated artefacts, keeping the raw feeds
	rm -f data/processed/*.parquet data/processed/*.json
	rm -rf .pytest_cache **/__pycache__
