# Contributing to ScopeGuard

Hard rule: **no feature may bypass scope enforcement.**

## Before you start

- Open an issue describing what you want to change and why
- Changes to `core/scope.py` or scan modules get a review focused on the safety model
- Small fixes can go straight to a PR

## Development setup

```bash
git clone https://github.com/<you>/scopeguard.git
cd scopeguard
python -m venv .venv
source .venv/Scripts/activate
pip install -e ".[dev]"
```

## Standards

- Python 3.11+, fully type-hinted
- `ruff check src tests` must be clean
- `pytest -q` must pass
- Every parser function must be pure: `parse(text) -> list[dict]`

## What we want

- New scan modules that respect the scope model
- New WiFi backends (macOS via `airport`, BSD)
- Plugin loading for custom checks
- SARIF output for CI integration
- Better finding classification (severity, CVE mapping)

## What we will reject

- Anything that cracks, injects, or deauths
- Anything that hides a target from the scope check
- Anything that sends scan data to a remote server
- Features that require disabling scope enforcement "for testing"

## Commit style

`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
