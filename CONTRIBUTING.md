# Contributing

Thanks for your interest in improving `spcedp`. This is an async Python SDK for
the Vanderbilt SPC EDP v2 alarm protocol.

## Development setup

Tooling is pinned with [mise](https://mise.jdx.dev), which installs
[uv](https://docs.astral.sh/uv/); uv then provisions the Python toolchain and
the project virtualenv.

```sh
mise install
```

There is no separate "install dependencies" step: `uv run` resolves the
environment on demand from `pyproject.toml` and `uv.lock`.

## Running the tests

```sh
uv run --extra test pytest
```

## Linting and type checking

Match CI exactly with:

```sh
uv run --extra dev ruff check spcedp/ tests/ examples/
uv run --extra dev ruff format --check spcedp/ tests/ examples/
uv run --extra dev pylint spcedp/
uv run --extra dev mypy
```

`ruff format` (without `--check`) applies formatting fixes locally. The same
checks are wired up as pre-commit hooks in `.pre-commit-config.yaml`; run them
with `prek run --all-files` (or the classic `pre-commit`).

## Before opening a pull request

- Keep changes fully type-annotated (`mypy` runs with
  `disallow_untyped_defs = true` over `spcedp/`).
- Ensure tests, ruff, pylint, and mypy all pass.
- Do not alter the reverse-engineered AES-128-ECB layout, the EDP checksum
  math, or any captured-frame test fixture; these encode real wire bytes.
- See [SECURITY.md](SECURITY.md) for how to report security issues privately
  rather than via a public issue or PR.
