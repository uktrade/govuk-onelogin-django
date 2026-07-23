import logging
from http import HTTPStatus
from typing import Any

from authlib.common.security import generate_token
from django.conf import settings
from django.contrib.auth import (
    REDIRECT_FIELD_NAME,
    SESSION_KEY,
    authenticate,
    get_user_model,
    login,
)
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import RedirectView, View
from joserfc import jwt
from joserfc.errors import DecodeError, InvalidClaimError
from joserfc.jwk import KeySet

from .types import AuthenticationLevel, IdentityConfidenceLevel
from .utils import (
    TOKEN_SESSION_KEY,
    delete_oauth_nonce,
    delete_oauth_state,
    get_client,
    get_client_id,
    get_oauth_state,
    get_oidc_config,
    get_token,
    store_oauth_nonce,
    store_oauth_state,
)

logger = logging.getLogger(__name__)
UserModel = get_user_model()


def get_trust_vector(
    auth_level: AuthenticationLevel, identity_level: IdentityConfidenceLevel
) -> dict[str, str]:
    return {"vtr": f'["{auth_level}.{identity_level}"]'}


REDIRECT_SESSION_FIELD_NAME = f"_oauth2_{REDIRECT_FIELD_NAME}"
BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_JTI_CACHE_KEY_PREFIX = "one_login_logout_token_jti"
LOGOUT_TOKEN_JTI_CACHE_TIMEOUT = 60 * 3


def get_next_url(request):
    """Copied straight from staff-sso-client.

    https://github.com/uktrade/django-staff-sso-client/blob/master/authbroker_client/views.py
    """
    next_url = request.GET.get(
        REDIRECT_FIELD_NAME, request.session.get(REDIRECT_SESSION_FIELD_NAME)
    )
    if next_url and url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts=settings.ALLOWED_HOSTS,
        require_https=request.is_secure(),
    ):
        return next_url

    return None


class AuthView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        client = get_client(self.request)
        config = get_oidc_config()

        nonce = generate_token()
        trust_vector = get_trust_vector(
            settings.GOV_UK_ONE_LOGIN_AUTHENTICATION_LEVEL,
            settings.GOV_UK_ONE_LOGIN_CONFIDENCE_LEVEL,
        )

        url, state = client.create_authorization_url(
            config.authorise_url,
            nonce=nonce,
            **trust_vector,
        )

        self.request.session[REDIRECT_SESSION_FIELD_NAME] = get_next_url(self.request)
        store_oauth_state(self.request, state)
        store_oauth_nonce(self.request, nonce)

        return url


class AuthCallbackView(View):
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        auth_code = self.request.GET.get("code", None)

        state = get_oauth_state(self.request)
        if not auth_code or not state:
            messages = {
                "auth_code": "Auth code returned from one_login",
                "no_auth_code": "No auth code returned from one_login",
                "state": "state found in session",
                "no_state": "no state found in session",
            }
            auth_code_msg = (
                messages["auth_code"] if auth_code else messages["no_auth_code"]
            )
            state_msg = messages["state"] if state else messages["no_state"]
            conjunction = "and" if not auth_code and not state else "but"
            msg = (
                "Redirecting to login, missing precondition(s):"
                f" {auth_code_msg} {conjunction} {state_msg}"
            )
            logger.warning(msg)
            return redirect(settings.LOGIN_URL)

        auth_service_state = self.request.GET.get("state")
        if state != auth_service_state:
            logger.error("Session state and passed back state differ")
            raise SuspiciousOperation("Session state and passed back state differ")

        try:
            token = get_token(self.request, auth_code)
        except InvalidClaimError:
            logger.error("Unable to validate token")
            raise SuspiciousOperation("Unable to validate token")

        # Save token to session: "authenticate" uses this to verify the user
        self.request.session[TOKEN_SESSION_KEY] = dict(token)
        delete_oauth_state(self.request)
        delete_oauth_nonce(self.request)

        # Get or create the user
        user = authenticate(request)

        # Get next_url from session before "login" (which is essentially caching the user in the
        # session), because login can clear the session if the session belongs to another user.
        # See https://github.com/django/django/blob/f0c269f285ab58bfb4a120141d7dd41ff4f42b45/django/contrib/auth/__init__.py#L175-L185
        # This happens if we have multiple auth backends and the user has already authenticated
        # with another one, for example in the case of a Staff SSO user then wanting to authenticate
        # with GOV.UK One Login.
        next_url = get_next_url(request) or getattr(settings, "LOGIN_REDIRECT_URL", "/")

        if user is not None:
            login(request, user)

            # Re-save token to session _after_ "login" (because login can clear the session as above)
            self.request.session[TOKEN_SESSION_KEY] = dict(token)

        return redirect(next_url)


@method_decorator(csrf_exempt, name="dispatch")
class OIDCBackChannelLogoutView(View):
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            user_sub = self.validate_logout_token()
        except DecodeError as err:
            logger.error(
                "OIDCBackChannelLogoutView: Unable to decode logout token: %s", err
            )
        except InvalidClaimError as err:
            logger.error("OIDCBackChannelLogoutView: Logout Token invalid: %s", err)
        except Exception as err:
            logger.error("OIDCBackChannelLogoutView: Unknown error %s", err)
        else:
            self.logout_user(user_sub)

        return HttpResponse(status=HTTPStatus.OK)

    def validate_logout_token(self) -> str:
        """Validate the logout token sent from GOV.UK One Login."""

        logout_token = self.request.POST.get("logout_token")
        config = get_oidc_config()

        decoded_token = self.decode_logout_token(logout_token, config)
        self.validate_logout_token_claims(decoded_token.claims, config)
        self.validate_logout_token_jti(decoded_token.claims["jti"])

        return decoded_token.claims["sub"]

    def decode_logout_token(self, logout_token: str | None, config):
        key_set = KeySet.import_key_set(
            {
                "keys": config.get_public_keys(),
            }
        )

        return jwt.decode(
            logout_token,
            key_set,
        )

    def validate_logout_token_claims(
        self,
        claims: dict[str, Any],
        config,
    ) -> None:
        claims_registry = jwt.JWTClaimsRegistry(
            iss={
                "essential": True,
                "value": config.issuer,
            },
            aud={
                "essential": True,
                "values": [get_client_id(self.request)],
            },
            sub={
                "essential": True,
            },
            events={
                "essential": True,
                "value": {
                    BACK_CHANNEL_LOGOUT_EVENT: {},
                },
            },
            jti={
                "essential": True,
            },
            exp={
                "essential": True,
            },
            iat={
                "essential": True,
            },
        )

        claims_registry.validate(claims)

    def validate_logout_token_jti(self, jti: str) -> None:
        cache_key = self.get_logout_token_jti_cache_key(jti)

        if cache.get(cache_key):
            raise InvalidClaimError("jti")

        cache.set(cache_key, True, timeout=LOGOUT_TOKEN_JTI_CACHE_TIMEOUT)

    def get_logout_token_jti_cache_key(self, jti: str) -> str:
        return f"{LOGOUT_TOKEN_JTI_CACHE_KEY_PREFIX}:{jti}"

    def logout_user(self, sub: str) -> None:
        user = UserModel.objects.filter(**{UserModel.USERNAME_FIELD: sub}).first()

        if not user:
            logger.error(
                "OIDCBackChannelLogoutView: Unable to log user out with sub: %s", sub
            )
            return

        user_sessions = []
        valid_sessions = Session.objects.filter(expire_date__gte=timezone.now())

        for session in valid_sessions:
            if str(user.pk) == session.get_decoded().get(SESSION_KEY):
                user_sessions.append(session.pk)

        Session.objects.filter(pk__in=user_sessions).delete()
