import logging
from http import HTTPStatus
from typing import Any

from authlib.common.security import generate_token
from authlib.jose import JWTClaims, jwt
from authlib.jose.errors import DecodeError, InvalidClaimError
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
    return {"vtr": f"['{auth_level}.{identity_level}']"}


REDIRECT_SESSION_FIELD_NAME = f"_oauth2_{REDIRECT_FIELD_NAME}"


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

        if not auth_code:
            logger.error("No auth code returned from one_login")
            return redirect(settings.LOGIN_URL)

        state = get_oauth_state(self.request)
        if not state:
            logger.error("No state found in session")
            raise SuspiciousOperation("No state found in session")

        auth_service_state = self.request.GET.get("state")
        if state != auth_service_state:
            logger.error("Session state and passed back state differ")
            raise SuspiciousOperation("Session state and passed back state differ")

        try:
            token = get_token(self.request, auth_code)
        except InvalidClaimError:
            logger.error("Unable to validate token")
            raise SuspiciousOperation("Unable to validate token")

        self.request.session[TOKEN_SESSION_KEY] = dict(token)
        delete_oauth_state(self.request)
        delete_oauth_nonce(self.request)

        # Get or create the user
        user = authenticate(request)

        if user is not None:
            login(request, user)

        next_url = get_next_url(request) or getattr(settings, "LOGIN_REDIRECT_URL", "/")

        return redirect(next_url)


class LogoutTokenClaims(JWTClaims):
    def validate_jti(self) -> None:
        jti = self.get("jti")
        if cache.has_key(jti):
            raise InvalidClaimError("jti")
        else:
            # Cache for three minutes
            cache.set(jti, 1, timeout=60 * 3)


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
            # Log user out of there was no error
            self.logout_user(user_sub)

        # Always return a 200 response to GOV.UK One Login
        return HttpResponse(status=HTTPStatus.OK)

    def validate_logout_token(self) -> str:
        """Validate the logout token sent from GOV.UK One Login.

        https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/managing-your-users-sessions/#validate-your-logout-token
        Performs the following steps:
            1. Validate that the JWT kid claim in the logout token header exists in the JWKS (JSON web key set) returned by the /jwks endpoint.
            2. Check the JWT alg header matches the value for the key you are using.
            3. Use the key to validate the signature on the logout token according to the JSON Web Signature Specification.
            4. Check the value of iss (issuer) matches the Issuer Identifier specified in GOV.UK One Login’s discovery endpoint.
            5. Check the aud (audience) claim is the same client ID you received when you registered your service to use GOV.UK One Login.
            6. Check the iat (issued at) claim is in the past.
            7. Check the exp (expiry) claim is in the future.
            8. Check the logout token contains a sub (subject identifier) claim, otherwise known as the unique ID of a user.
            9. Check the logout token contains an events claim, which should be a JSON object with a single key:
               http://schemas.openid.net/event/backchannel-logout – the value for the key should be an empty object.
            10. Check your service has not received another logout token with the same jti claim in the last 3 minutes.
        """

        logout_token = self.request.POST.get("logout_token")
        config = get_oidc_config()

        claim_options = {
            "iss": {"essential": True, "value": config.issuer},
            "aud": {"essential": True, "value": get_client_id(self.request)},
            "sub": {"essential": True},
            "events": {
                "essential": True,
                "value": {"http://schemas.openid.net/event/backchannel-logout": {}},
            },
            "jti": {"essential": True},
        }

        claims = jwt.decode(
            logout_token,
            config.get_public_keys(),
            claims_cls=LogoutTokenClaims,
            claims_options=claim_options,
        )

        claims.validate()

        return claims["sub"]

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
            # SESSION_KEY == ""_auth_user_id""
            if str(user.pk) == session.get_decoded().get(SESSION_KEY):
                user_sessions.append(session.pk)

        Session.objects.filter(pk__in=user_sessions).delete()
