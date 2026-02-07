# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cidrize is a single-file Python library ("IP address parsing for humans") that wraps `netaddr` to intelligently parse various IP address notations into `netaddr.IPNetwork` objects. It also provides a `cidr` CLI tool.

## Build & Development Commands

This project uses **uv** with a **setuptools** backend.

```bash
# Install dependencies
uv sync

# Run all tests
uv run pytest

# Run a specific test
uv run pytest tests/test_cidrize.py::TestCidrize::test_cidr_style_ipv4

# Lint
ruff check cidrize.py tests/

# Format
ruff format cidrize.py tests/

# Run the CLI
uv run cidr 1.2.3.4/24

# Build the package
uv build
```

## Architecture

The entire library is a single module: `cidrize.py`. There is no package directory.

**Parsing flow in `cidrize()`:** The main function tries formats in order: CIDR → full range → IPv6 range → last-octet hyphen → glob/wildcard → bracket notation. Each format has a pre-compiled regex (`RE_CIDR`, `RE_RANGE`, `RE_GLOB`, etc.) and a dedicated parse function. On match, it returns a list of `netaddr.IPNetwork` objects.

**Strict vs. loose mode:** `strict=False` (default) returns a spanning CIDR that covers the input range. `strict=True` returns the exact constituent networks. Ranges larger than /16 (`MAX_RANGE_LEN = 65535`) force strict mode regardless.

**Key public API** (defined in `__all__`): `cidrize()`, `parse_range()`, `is_ipv6()`, `normalize_address()`, `optimize_network_range()`, `dump()`, `output_str()`, `CidrizeError`.

**CLI entry point:** `cidr` command is defined in `main()` at the bottom of `cidrize.py`, registered via `[project.scripts]` in `pyproject.toml`.

**Tests:** `tests/test_cidrize.py` contains pytest classes that import `cidrize` directly (the module is at the repo root).

## Code Style

- **Ruff** for both linting and formatting (line length 88, target Python 3.10+)
- Configuration in `pyproject.toml` under `[tool.ruff]`

## CI/CD & Release

- GitHub Actions workflows in `.github/workflows/`
- **ci.yml** — runs tests + ruff on push/PR
- **release.yml** — automated releases via `python-semantic-release`
- **release-preview.yml** — dry-run release preview on PRs
- Uses **conventional commits** (`feat:`, `fix:`, `perf:`, etc.) for automatic versioning
- Dependabot configured for dependency updates

## Git Workflow

- Use **git worktrees** for feature branches — create worktrees under `.worktrees/` (e.g., `.worktrees/feat-foo`)
- Commit in the worktree, not in the main working directory
