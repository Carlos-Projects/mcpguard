# Verification

## Minimal Check

Run this before claiming a change works:

```bash
python3 -m pytest tests/ -v
```

## Full Check

```bash
ruff check .
mypy mcpguard/
python3 -m pytest tests/ -v
```

## Security Check

```bash
git status --short
git diff --check
rg -n "(api[_-]?key|token|secret|password)\\s*[:=]\\s*['\\\"][^'\\\"]+" .
```

## Evidence Standard

Paste only summaries in chat. Keep full outputs in `reports/` when useful.
