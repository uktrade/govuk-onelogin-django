import logging
from http import HTTPStatus
from unittest import mock

import freezegun
import pytest
from authlib.jose.errors import InvalidClaimError
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.test import Client, override_settings
from django.urls import reverse

from govuk_onelogin_django.utils import TOKEN_SESSION_KEY, OneLoginConfig
from govuk_onelogin_django.views import REDIRECT_SESSION_FIELD_NAME

FAKE_OPENID_CONFIG_URL = "https://oidc.onelogin.gov.uk/.well-known/openid-configuration"
FAKE_AUTHORIZE_URL = "https://oidc.onelogin.gov.uk/authorize"
FAKE_JWKS_URI = "https://oidc.onelogin.gov.uk/.well-known/jwks.json"


@pytest.fixture(autouse=True, scope="class")
def correct_settings():
    """Ensure One Login is enabled for all tests"""
    with override_settings(
        GOV_UK_ONE_LOGIN_ENABLED=True,
        GOV_UK_ONE_LOGIN_OPENID_CONFIG_URL=FAKE_OPENID_CONFIG_URL,
    ):
        yield None

    cache.delete(OneLoginConfig.CACHE_KEY)


@pytest.fixture(autouse=True)
def openid_config(requests_mock):
    requests_mock.get(
        FAKE_OPENID_CONFIG_URL,
        json={
            "authorization_endpoint": FAKE_AUTHORIZE_URL,
            "token_endpoint": "",
            "userinfo_endpoint": "",
            "end_session_endpoint": "",
            "issuer": "https://oidc.integration.account.gov.uk/",
            "jwks_uri": FAKE_JWKS_URI,
        },
    )


class TestAuthView:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        self.client = client
        self.url = reverse("one_login:login")

    def test_auth_view(self):
        response = self.client.get(self.url)

        assert response.status_code == HTTPStatus.FOUND
        assert FAKE_AUTHORIZE_URL in response.url

    def test_auth_view_retains_next_url(self):
        response = self.client.get(self.url + "?next=/workbasket/")
        assert response.status_code == HTTPStatus.FOUND
        assert self.client.session[REDIRECT_SESSION_FIELD_NAME] == "/workbasket/"

    def test_auth_view_retains_unsafe_next_url(self):
        response = self.client.get(self.url + "?next=https://danger.com")
        assert response.status_code == HTTPStatus.FOUND
        assert not self.client.session[REDIRECT_SESSION_FIELD_NAME]


class TestAuthCallbackView:
    @pytest.fixture(autouse=True)
    def setup(self, db, client):
        self.client = client
        self.url = reverse("one_login:callback")

    @mock.patch.multiple(
        "govuk_onelogin_django.views",
        get_oauth_state=mock.DEFAULT,
        get_token=mock.DEFAULT,
        authenticate=mock.DEFAULT,
        login=mock.DEFAULT,
        autospec=True,
    )
    def test_auth_callback_view(self, **mocks):
        auth_code = "fake-auth-code"
        state = "fake-state"

        mocks["get_oauth_state"].return_value = state
        mocks["get_token"].return_value = {"token": "fake"}

        response = self.client.get(f"{self.url}?code={auth_code}&state={state}")

        assert self.client.session[TOKEN_SESSION_KEY] == {"token": "fake"}
        assert response.status_code == HTTPStatus.FOUND
        assert response.url == settings.LOGIN_REDIRECT_URL

    @mock.patch.multiple(
        "govuk_onelogin_django.views",
        get_oauth_state=mock.DEFAULT,
        get_token=mock.DEFAULT,
        authenticate=mock.DEFAULT,
        login=mock.DEFAULT,
        autospec=True,
    )
    def test_auth_callback_view_with_next_url(self, **mocks):
        next_url = "/something"

        # Magic session variable dance to persist session
        # https://docs.djangoproject.com/en/4.2/topics/testing/tools/#django.test.Client.session
        session = self.client.session
        session[REDIRECT_SESSION_FIELD_NAME] = next_url
        session.save()

        auth_code = "fake-auth-code"
        state = "fake-state"
        mocks["get_oauth_state"].return_value = state
        mocks["get_token"].return_value = {"token": "fake"}

        response = self.client.get(f"{self.url}?code={auth_code}&state={state}")

        assert self.client.session[TOKEN_SESSION_KEY] == {"token": "fake"}
        assert response.status_code == HTTPStatus.FOUND
        assert response.url == next_url

    def test_auth_callback_view_no_code(self, caplog):
        response = self.client.get(f"{self.url}")

        assert response.status_code == HTTPStatus.FOUND
        assert response.url == settings.LOGIN_URL
        assert caplog.messages[0] == "No auth code returned from one_login"

    def test_auth_callback_view_no_session_state(self, caplog):
        auth_code = "fake-auth-code"
        state = "fake-state"

        response = self.client.get(f"{self.url}?code={auth_code}&state={state}")
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert caplog.messages[0] == "No state found in session"

    @mock.patch.multiple(
        "govuk_onelogin_django.views", get_oauth_state=mock.DEFAULT, autospec=True
    )
    def test_auth_callback_view_invalid_state(self, caplog, **mocks):
        auth_code = "fake-auth-code"
        state = "invalid-fake-state"
        mocks["get_oauth_state"].return_value = "fake-state"

        response = self.client.get(f"{self.url}?code={auth_code}&state={state}")
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert caplog.messages[0] == "Session state and passed back state differ"

    @mock.patch.multiple(
        "govuk_onelogin_django.views",
        get_oauth_state=mock.DEFAULT,
        get_token=mock.DEFAULT,
        autospec=True,
    )
    def test_auth_callback_view_invalid_token(self, caplog, **mocks):
        auth_code = "fake-auth-code"
        state = "fake-state"

        mocks["get_oauth_state"].return_value = state
        mocks["get_token"].side_effect = InvalidClaimError("claim_value")

        response = self.client.get(f"{self.url}?code={auth_code}&state={state}")
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert caplog.messages[0] == "Unable to validate token"


class TestOIDCBackChannelLogoutView:
    # A test known sub from a now deleted test account
    TEST_SUB = "urn:fdc:gov.uk:2022:WAWdm8d0W_e8d2Pd9JszlvBDzHEWb1Y4U5pGaWXo6tc"
    # A test known logout token for a now deleted test account
    TEST_PAYLOAD = (
        "eyJraWQiOiI2NDRhZjU5OGI3ODBmNTQxMDZjYTBmM2MwMTczNDFiYzIzMGM0ZjgzNzNmMz"
        "VmMzJlMThlM2U0MGNjN2FjZmY2IiwidHlwIjoibG9nb3V0K2p3dCIsImFsZyI6IkVTMjU2"
        "In0.eyJhdWQiOiJ3MFNHMFM4UEotNHZkZVctTmFta3pVcy1EYUEiLCJzdWIiOiJ1cm46Zm"
        "RjOmdvdi51azoyMDIyOldBV2RtOGQwV19lOGQyUGQ5SnN6bHZCRHpIRVdiMVk0VTVwR2FX"
        "WG82dGMiLCJpc3MiOiJodHRwczovL29pZGMuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudW"
        "svIiwiZXhwIjoxNzM2NzY1NDQzLCJpYXQiOjE3MzY3NjUzMjMsImp0aSI6IjVjYjc1MDZi"
        "LTgzZWMtNGJkOS1hMjM1LTJkZmRiZmM2ZjA3YyIsImV2ZW50cyI6eyJodHRwOi8vc2NoZW"
        "1hcy5vcGVuaWQubmV0L2V2ZW50L2JhY2tjaGFubmVsLWxvZ291dCI6e319fQ._JqrsSuX5"
        "W_jSUAqbIIqE1ziYahlYNLYq_LIbPQbO170OALf6p7m9OQnHbQdlmMod885rqLiDjkbf6B"
        "qynJSzA"
    )

    @pytest.fixture(autouse=True)
    def setup(self, db, requests_mock):
        # clear cache to prevent JSI error (for different tests using the same payload)
        cache.clear()

        # CSRF is disabled in one_login:back-channel-logout so check disabling it works.
        self.client = Client(enforce_csrf_checks=True)
        self.url = reverse("one_login:back-channel-logout")
        self.user = User.objects.create_user(
            self.TEST_SUB, "test_user@example.com", "fake-password"
        )

        # Fake response from jwks endpoint to known value
        requests_mock.get(FAKE_JWKS_URI, json=self._jwts_json())

        # Login the created user with a separate client instance to create a session
        client = Client()
        assert Session.objects.count() == 0
        client.force_login(self.user)
        assert Session.objects.count() == 1

        session = Session.objects.first().get_decoded()
        assert str(self.user.pk) == session["_auth_user_id"]

    def test_post_only(self):
        response = self.client.get(self.url)

        assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED

    @freezegun.freeze_time("2025-1-13 10:49:00")
    def test_oidc_back_channel_logout_successful(self, caplog):
        # Check the user session has been removed after the back-channel logout request.
        assert Session.objects.count() == 1
        response = self.client.post(self.url, data={"logout_token": self.TEST_PAYLOAD})
        assert Session.objects.count() == 0

        assert response.status_code == HTTPStatus.OK

        # Check duplicate call is caught (invalid claim error).
        response = self.client.post(self.url, data={"logout_token": self.TEST_PAYLOAD})
        assert response.status_code == HTTPStatus.OK
        assert caplog.record_tuples == [
            (
                "govuk_onelogin_django.views",
                logging.ERROR,
                "OIDCBackChannelLogoutView: Logout Token invalid: invalid_claim: Invalid claim 'jti'",
            )
        ]

    def test_unknown_error(self, caplog):
        response = self.client.post(self.url, data={"logout_token": self.TEST_PAYLOAD})
        assert response.status_code == HTTPStatus.OK

        assert caplog.record_tuples == [
            (
                "govuk_onelogin_django.views",
                logging.ERROR,
                "OIDCBackChannelLogoutView: Unknown error expired_token: The token is expired",
            )
        ]

    def test_decode_error(self, caplog):
        response = self.client.post(self.url, data={"logout_token": "eyJraWQiOi"})
        assert response.status_code == HTTPStatus.OK

        assert caplog.record_tuples == [
            (
                "govuk_onelogin_django.views",
                logging.ERROR,
                "OIDCBackChannelLogoutView: Unable to decode logout token: Invalid input segments length: ",
            )
        ]

    @freezegun.freeze_time("2025-1-13 10:49:00")
    def test_oidc_back_channel_logout_user_sub_error(self, caplog):
        self.user.username = "test_user_name"
        self.user.save()

        response = self.client.post(self.url, data={"logout_token": self.TEST_PAYLOAD})
        assert response.status_code == HTTPStatus.OK

        assert caplog.record_tuples == [
            (
                "govuk_onelogin_django.views",
                logging.ERROR,
                "OIDCBackChannelLogoutView: Unable to log user out with sub: urn:fdc:gov.uk:2022:WAWdm8d0W_e8d2Pd9JszlvBDzHEWb1Y4U5pGaWXo6tc",
            )
        ]

    def _jwts_json(self):
        """This is ok to hardcode as it's a publicly available public key."""
        return {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": "644af598b780f54106ca0f3c017341bc230c4f8373f35f32e18e3e40cc7acff6",
                    "x": "5URVCgH4HQgkg37kiipfOGjyVft0R5CdjFJahRoJjEw",
                    "y": "QzrvsnDy3oY1yuz55voaAq9B1M5tfhgW3FBjh_n_F0U",
                    "alg": "ES256",
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": "e1f5699d068448882e7866b49d24431b2f21bf1a8f3c2b2dde8f4066f0506f1b",
                    "x": "BJnIZvnzJ9D_YRu5YL8a3CXjBaa5AxlX1xSeWDLAn9k",
                    "y": "x4FU3lRtkeDukSWVJmDuw2nHVFVIZ8_69n4bJ6ik4bQ",
                    "alg": "ES256",
                },
                {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "sig",
                    "kid": "76e79bfc350137593e5bd992b202e248fc97e7a20988a5d4fbe9a0273e54844e",
                    "alg": "RS256",
                    "n": "lGac-hw2cW5_amtNiDI-Nq2dEXt1x0nwOEIEFd8NwtYz7ha1GzNwO2LyFEoOvqIAcG0NFCAxgjkKD5QwcsThGijvMOLG3dPRMjhyB2S4bCmlkwLpW8vY4sJjc4bItdfuBtUxDA0SWqepr5h95RAsg9UP1LToJecJJR_duMzN-Nutu9qwbpIJph8tFjOFp_T37bVFk4vYkWfX-d4-TOImOOD75G0kgYoAJLS2SRovQAkbJwC1bdn_N8yw7RL9WIqZCwzqMqANdo3dEgSb04XD_CUzL0Y2zU3onewH9PhaMfb11JhsuijH3zRA0dwignDHp7pBw8uMxYSqhoeVO6V0jz8vYo27LyySR1ZLMg13bPNrtMnEC-LlRtZpxkcDLm7bkO-mPjYLrhGpDy7fSdr-6b2rsHzE_YerkZA_RgX_Qv-dZueX5tq2VRZu66QJAgdprZrUx34QBitSAvHL4zcI_Qn2aNl93DR-bT8lrkwB6UBz7EghmQivrwK84BjPircDWdivT4GcEzRdP0ed6PmpAmerHaalyWpLUNoIgVXLa_Px07SweNzyb13QFbiEaJ8p1UFT05KzIRxO8p18g7gWpH8-6jfkZtTOtJJKseNRSyKHgUK5eO9kgvy9sRXmmflV6pl4AMOEwMf4gZpbKtnLh4NETdGg5oSXEuTiF2MjmXE",
                },
            ]
        }
