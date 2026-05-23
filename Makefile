.PHONY: install dev-install test lint typecheck clean format

install:
	pip install .

dev-install:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --ignore=tests/test_integration_stdio.py -x

test-all:
	python -m pytest tests/ -v -x

lint:
	ruff check .

format:
	ruff check --fix .

typecheck:
	mypy mcpguard/ --ignore-missing-imports

check: lint typecheck test

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf mcpguard_logs/
