# Example project
Example project showing how to integrate GOV.UK One Login in to a Django application

## Installation
- Build the local govuk_onelogin_django package:
```bash
# In project root build the package (as in one directory up from the example_project directory)
uv build

# Change directory to example_project and install
cd example_project
uv sync
uv add --no-cache --find-links ../dist govuk_onelogin_django
```

- Run migrations:
```bash
uv run manage.py migrate
```

- Run the test server:
```bash
uv run manage.py runserver
```
