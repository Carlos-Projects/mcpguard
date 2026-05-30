# Contributing to MCPGuard

👋 **Welcome, and thank you for considering contributing to MCPGuard!**

Every contribution — whether it's a bug fix, new feature, documentation improvement, or just asking a good question — helps make AI agent security stronger for everyone. We're thrilled to have you here.

## First Time Contributor?

No worries! We all start somewhere. Here are some great ways to begin:

- Look for issues labeled `good first issue` or `help wanted`
- Improve our documentation or README
- Add more tests to increase coverage
- Ask questions in GitHub Discussions — there are no silly questions

We maintain a welcoming, inclusive community. If you ever feel stuck, just ask.

## Need Help?

If you have questions or run into trouble:

- Open a [GitHub Issue](https://github.com/Carlos-Projects/mcpguard/issues)
- Check existing issues to see if someone else had the same question
- Be as descriptive as possible — include your environment, steps to reproduce, and what you expected to happen

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

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
