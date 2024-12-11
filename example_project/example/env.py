from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from govuk_onelogin_django.types import AuthenticationLevel, IdentityConfidenceLevel


class Environment(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore",
        validate_default=False,
    )
    gov_uk_one_login_client_id: str
    gov_uk_one_login_client_secret: str
    gov_uk_one_login_openid_config_url: HttpUrl
    gov_uk_one_login_scope: str
    gov_uk_one_login_authentication_level: AuthenticationLevel = (
        AuthenticationLevel.MEDIUM_LEVEL
    )
    gov_uk_one_login_confidence_level: IdentityConfidenceLevel = (
        IdentityConfidenceLevel.NONE
    )


env = Environment(_env_file=".env")
