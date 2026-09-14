# Core commands for initialising project and building package
init:
	uv sync --no-install-project

build:
	uv build --no-sources

##@ Linting & formatting
ruff-check: ## Run the Ruff linter
	uv run ruff check

ruff-check-fix: ## Run the Ruff linter and resolve fixable errors
	uv run ruff check --fix

ruff-format: ## Run the Ruff formatter
	make ruff-check-fix
	uv run ruff format

ty-check: ## Run ty type checker
	uv run ty check

# Commands for running tests and coverage
test:
	uv run pytest

coverage:
	uv run coverage run --source=govuk_onelogin_django -m pytest

coverage-html:
	uv run coverage html
