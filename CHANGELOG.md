# CHANGELOG


## v3.0.0 (2026-02-07)

### Bug Fixes

- Migrate from Poetry/Black/Pylint to uv/Ruff/setuptools
  ([`0d8c1d0`](https://github.com/jathanism/cidrize/commit/0d8c1d0ee7fa550b6d8a7c40b52d3107314bf665))

BREAKING CHANGE: Drop support for Python < 3.10.

- Replace Poetry with uv + setuptools build backend - Replace Black + Pylint with Ruff for linting
  and formatting - Add GitHub Actions CI/CD: ci.yml, release.yml, release-preview.yml - Configure
  python-semantic-release for automated versioning - Convert docs from RST to Markdown (README,
  LICENSE, CHANGELOG) - Remove dead code: unused exception classes (NotCIDRStyle, NotRangeStyle,
  NotGlobStyle, NotBracketStyle), netaddr_to_ipy(), EVERYTHING alias - Replace optparse with
  argparse in CLI - Add output_str to __all__ - Remove pylint disable comments - Delete
  renovate.json (using Dependabot), .travis.yml, old workflow - Remove tests/cidrize.py symlink (no
  longer needed)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

### Breaking Changes

- Drop support for Python < 3.10.


## v2.1.1 (2026-02-06)

### Bug Fixes

- Relaxing bracket regex to allow intended square bracket inputs.
  ([`81eb34b`](https://github.com/jathanism/cidrize/commit/81eb34b6b9ccc7dd3e31db4f474e701ba4449e76))


## v2.1.0 (2023-02-17)


## v2.0.0 (2021-03-30)
