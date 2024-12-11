from govuk_onelogin_django.types import AuthenticationLevel, IdentityConfidenceLevel

SECRET_KEY = "fake-key"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "govuk_onelogin_django",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]


ROOT_URLCONF = "govuk_onelogin_django.tests.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "test.db",
    }
}

USE_TZ = True

# govuk_onelogin_django settings
GOV_UK_ONE_LOGIN_AUTHENTICATION_LEVEL = AuthenticationLevel.MEDIUM_LEVEL
GOV_UK_ONE_LOGIN_CONFIDENCE_LEVEL = IdentityConfidenceLevel.NONE
