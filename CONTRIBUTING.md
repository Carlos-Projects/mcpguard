# Contributing

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/mcpguard.git
cd mcpguard
pip install -e ".[dev]"
pre-commit install
```

## Workflow

1. Create a branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Run checks: `make check`
4. Add tests for new functionality
5. Commit: `git commit -m "description"`
6. Push and open a PR

## Quality Gates

Before submitting a PR, ensure:

- `make lint` — ruff passes
- `make typecheck` — mypy passes
- `make test` — all tests pass
- Tests added for new features

## Code Style

- Line length: 120
- Ruff enforces imports, naming, and formatting automatically
- Type hints required for all public functions

## Pull Request Process

1. Use the PR template
2. Keep PRs focused on a single change
3. Reference related issues
4. Squash commits before merging
