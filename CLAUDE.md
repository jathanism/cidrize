# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cidrize is a single-file Python library ("IP address parsing for humans") that wraps `netaddr` to intelligently parse various IP address notations into `netaddr.IPNetwork` objects. It also provides a `cidr` CLI tool.

## Build & Development Commands

This project uses **Poetry** for dependency management.

```bash
# Install dependencies
poetry install

# Run all tests (includes Black formatting check + Pylint linting)
poetry run pytest

# Run a specific test
poetry run pytest tests/test_cidrize.py::TestCidrize::test_cidr_style_ipv4

# Format code
poetry run black cidrize.py tests/

# Run the CLI
poetry run cidr 1.2.3.4/24
```

## Architecture

The entire library is a single module: `cidrize.py` (~695 lines). There is no package directory.

**Parsing flow in `cidrize()`:** The main function tries formats in order: CIDR → full range → IPv6 range → last-octet hyphen → glob/wildcard → bracket notation. Each format has a pre-compiled regex (`RE_CIDR`, `RE_RANGE`, `RE_GLOB`, etc.) and a dedicated parse function. On match, it returns a list of `netaddr.IPNetwork` objects.

**Strict vs. loose mode:** `strict=False` (default) returns a spanning CIDR that covers the input range. `strict=True` returns the exact constituent networks. Ranges larger than /16 (`MAX_RANGE_LEN = 65535`) force strict mode regardless.

**Key public API** (defined in `__all__`): `cidrize()`, `parse_range()`, `is_ipv6()`, `normalize_address()`, `optimize_network_range()`, `dump()`, `output_str()`, `CidrizeError`.

**CLI entry point:** `cidr` command is defined in `main()` at the bottom of `cidrize.py`, registered via `[tool.poetry.scripts]`.

**Tests:** `tests/test_cidrize.py` contains pytest classes. Note: `tests/cidrize.py` is a symlink to `../cidrize.py` so tests can import the module directly.

## Code Style

- **Black** with 80-char line length, targeting Python 3.7+
- **Pylint** with `missing-class-docstring` disabled; no docstrings required for private methods, test functions, or inner Meta classes
- Both checks run automatically as part of `poetry run pytest` via `pytest-black` and `pytest-pylint`
