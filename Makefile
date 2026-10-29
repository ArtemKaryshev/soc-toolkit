.PHONY: install dev test lint types check ui data

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov --cov-report=term-missing

lint:
	ruff check src tests scripts

types:
	mypy

check: lint types test

ui:
	soc-toolkit ui

# Пересобрать встроенные справочники из локальных исходников (см. scripts/build_reference_data.py)
data:
	python scripts/build_reference_data.py --mitre $(MITRE) --lolbas-dir $(LOLBAS)
