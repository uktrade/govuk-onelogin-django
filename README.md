# govuk-onelogin-django
OpenID Connect client that works with GOV.UK One Login.

Package provides the following endpoints:
- `one-login/login/` to login via GOV.UK One Login.
- `one-login/callback/` endpoint GOV.UK One Login will send logged-in users back to.

The example project also provides an [example logout view](example_project/example/views.py) that will log the user out of your service as well as GOV.UK One Login.

See `class ExampleLogoutView` for example that includes `post_logout_redirect_uri`

## Documentation:
- GOV.UK One Login admin tool used to create a test application: https://admin.sign-in.service.gov.uk/
- GOV.UK One Login documentation: https://www.sign-in.service.gov.uk/documentation
- GOV.UK One Login technical documentation: https://docs.sign-in.service.gov.uk/


## Quick start
Before starting, you should create an example app using the GOV.OK One Login [admin tool](https://admin.sign-in.service.gov.uk/).

1. Add "govuk_onelogin_django" to your INSTALLED_APPS setting like this:
    ```python
    INSTALLED_APPS = [
        ...,
        "govuk_onelogin_django",
    ]
    ```
2. Include the govuk_onelogin_django URLconf in your project urls.py like this:
    ```python
    path("one-login/", include("govuk_onelogin_django.urls")),
    ```
3. Include OneLoginBackend to your AUTHENTICATION_BACKENDS like this:
    ```python
    AUTHENTICATION_BACKENDS.append("govuk_onelogin_django.backends.OneLoginBackend")
    ```

4. Include the following settings in your settings.py file
    ```python
    # Required start page that includes a link to log in to GOV.UK One Login
    LOGIN_URL = "your-login-start-page"
    # A view name that the logged-in user will be redirected to after logging in via GOV.UK One Login
    LOGIN_REDIRECT_URL = "view-to-send-logged-in-users-to"

    # All other GOV.UK One Login settings required to configure govuk-onelogin-django
    GOV_UK_ONE_LOGIN_CLIENT_ID = "Your client ID"
    GOV_UK_ONE_LOGIN_CLIENT_SECRET = "Your client secret"
    GOV_UK_ONE_LOGIN_OPENID_CONFIG_URL = "Either integration or production config url."
    GOV_UK_ONE_LOGIN_SCOPE = "Required scopes"
    GOV_UK_ONE_LOGIN_AUTHENTICATION_LEVEL = "Required authentication level"
    GOV_UK_ONE_LOGIN_CONFIDENCE_LEVEL = "Required confidence level"
    ```
    **Note:** `GOV_UK_ONE_LOGIN_CLIENT_SECRET` is a base64 encoded string of your private key. e.g. `base64 -i private_key.pem`

    See [this document](https://docs.sign-in.service.gov.uk/before-integrating/set-up-your-public-and-private-keys/#set-up-your-public-and-private-keys) detailing how to generate your keys.

5. Alternatively see the example_project [README.md](example_project/README.md) for details on how to build and run the example project.


## Commands to build and test govuk-onelogin-django
- Install [uv](https://docs.astral.sh/uv/)
- Update the project's environment: `uv sync`
- Run tests using local venv: `uv run pytest`
- Running the tests against all supported python versions:
  - Install tox and tox-uv: `uv tool install tox --with tox-uv`
  - Check tox is installed: `tox --version`
  - run the tests: `tox run`
- Install pre-commit hooks: `uv run pre-commit install`
- Run pre-commit against all files: `uv run pre-commit run --all-files`

## linting / formatting
- Run the Ruff linter: `uv run ruff check`
- Resolve fixable errors: `uv run ruff check --fix`
- Run the Ruff formatter: `uv run ruff format`
- mypy: `uv run mypy --config-file=pyproject.toml`

## Publishing
- Publish to PyPI: `uv publish --token <token>`
