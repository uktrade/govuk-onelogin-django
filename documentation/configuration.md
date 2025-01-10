# Configuring govuk-onelogin-django

Several areas of the package can be configured and are detailed below.

## The GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH setting

The GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH setting can be set to define a set of function to override particular settings.

The supported functions are the following:
- `def get_one_login_config() -> type[OneLoginConfig]:`
- `def get_one_login_client_id(request: HttpRequest) -> str:`
- `def get_one_login_client_secret(request: HttpRequest) -> str:`

Here is an example showing how to configure each one:

1. Create a module e.g. `auth/utils.py`
2. Set `GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH="auth.utils"` in your settings.
3. Add the following to `auth/utils.py`:

```python
def get_one_login_config() -> type[OneLoginConfig]:
    if some_condition:
        return CustomOneLoginConfig
    else:
        return OneLoginConfig

def get_one_login_client_id(request: HttpRequest) -> str:
    if some_condition:
        return "foo"
    else:
        return "bar"


def get_one_login_client_secret(request: HttpRequest) -> str:
        if some_condition:
        return "foo"
    else:
        return "bar"
```

## Overriding the back-channel-logout/ endpoint

The default implementation of back-channel-logout/ assumes `django.contrib.sessions.backends.db` is used for `SESSION_ENGINE`.

If you need to customise the behaviour of back-channel-logout/ then do the following:

1. In settings.py disable the default view provided by govuk-onelogin-django:
`GOV_UK_ONE_LOGIN_BACK_CHANNEL_ENABLED=False`
2. Create a custom view to override the default `logout_user` behaviour
```python
import logging

from govuk_onelogin_django.views import OIDCBackChannelLogoutView

from django.core.cache import cache
from django.contrib.auth import get_user_model, SESSION_KEY
from django.contrib.sessions.backends.cache import KEY_PREFIX

logger = logging.getLogger(__name__)
UserModel = get_user_model()


class CustomOIDCBackChannelLogoutView(OIDCBackChannelLogoutView):
    def logout_user(self, sub: str) -> None:
        user = UserModel.objects.filter(**{UserModel.USERNAME_FIELD: sub}).first()

        if not user:
            logger.error(
                "OIDCBackChannelLogoutView: Unable to log user out with sub: %s", sub
            )
            return


        user_sessions = []
        for key in cache.keys(f"{KEY_PREFIX}*"):
            session = cache.get(key)

            if str(user.pk) == session.get(SESSION_KEY):
                user_sessions.append(key)

        cache.delete_many(user_sessions)
```
3. Enable the custom view in your urls.py
```python
urlpatterns = [
    ...,
    path("back-channel-logout/", CustomOIDCBackChannelLogoutView.as_view(), name="back-channel-logout"),
]
```

The above example will work when `django.contrib.sessions.backends.cache` is used for `SESSION_ENGINE`.
