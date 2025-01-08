test:
	uv run pytest

init:
	uv sync --no-install-project

build:
	uv build --no-sources
