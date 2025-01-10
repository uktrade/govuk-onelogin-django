from typing import Any
from unittest import mock

from django.http import HttpRequest
from django.test import override_settings
from django.test.client import Client, RequestFactory

from govuk_onelogin_django.utils import (
    TOKEN_SESSION_KEY,
    OneLoginConfig,
    get_client_id,
    get_client_secret,
    get_oidc_config,
    get_one_login_logout_url,
)


@mock.patch.multiple(
    "govuk_onelogin_django.utils", OneLoginConfig=mock.DEFAULT, autospec=True
)
def test_get_one_login_logout_url(
    db, client: Client, rf: RequestFactory, **mocks: Any
) -> None:
    mocks[
        "OneLoginConfig"
    ].return_value.end_session_url = "https://fake-one.login.gov.uk/logout/"

    request = rf.request()
    request.session = client.session
    request.session[TOKEN_SESSION_KEY] = {"id_token": "FAKE-TOKEN"}
    request.session.save()

    # Test without post logout callback url
    assert get_one_login_logout_url(request) == "https://fake-one.login.gov.uk/logout/"

    # Test with post logout callback url
    expected = "https://fake-one.login.gov.uk/logout/?id_token_hint=FAKE-TOKEN&post_logout_redirect_uri=https%3A%2F%2Fmy-site-post-logout-redirect%2F"
    actual = get_one_login_logout_url(request, "https://my-site-post-logout-redirect/")

    assert expected == actual


class CustomOneLoginConfig(OneLoginConfig):
    pass


def get_one_login_config() -> type[OneLoginConfig]:
    return CustomOneLoginConfig


def get_one_login_client_id(request: HttpRequest) -> str:
    return "custom-test-client-id"


def get_one_login_client_secret(request: HttpRequest) -> str:
    return "custom-test-client-secret"


@override_settings(GOV_UK_ONE_LOGIN_CLIENT_ID="test-client-id")
def test_get_client_id():
    client_id = get_client_id(mock.Mock())
    assert client_id == "test-client-id"


@override_settings(
    GOV_UK_ONE_LOGIN_CLIENT_ID="test-client-id",
    GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH="govuk_onelogin_django.tests.test_utils",
)
def test_get_client_id_custom():
    client_id = get_client_id(mock.Mock())
    assert client_id == "custom-test-client-id"


def test_get_oidc_config():
    config_cls = get_oidc_config()
    assert isinstance(config_cls, OneLoginConfig)


@override_settings(
    GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH="govuk_onelogin_django.tests.test_utils"
)
def test_get_oidc_config_custom():
    config_cls = get_oidc_config()
    assert isinstance(config_cls, CustomOneLoginConfig)


@override_settings(GOV_UK_ONE_LOGIN_CLIENT_SECRET="test-client-secret")
def test_get_client_secret():
    client_secret = get_client_secret(mock.Mock())
    assert client_secret == "test-client-secret"


@override_settings(
    GOV_UK_ONE_LOGIN_CLIENT_SECRET="test-client-secret",
    GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH="govuk_onelogin_django.tests.test_utils",
)
def test_get_client_secret_custom():
    client_secret = get_client_secret(mock.Mock())
    assert client_secret == "custom-test-client-secret"
