from django.apps import AppConfig
from .logging import enable_logout_logging


class OneLoginConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "govuk_onelogin_django"
    label = "one_login"

    def ready(self):
        enable_logout_logging()
