# Core commands for initialising project and building package
init:
	uv sync --no-install-project

build:
	uv build --no-sources

# Commands for running tests and coverage
test:
	uv run pytest

coverage:
	uv run coverage run --source=govuk_onelogin_django -m pytest

coverage-html:
	uv run coverage html
