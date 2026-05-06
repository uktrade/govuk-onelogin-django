from django.http import HttpRequest
from django_log_formatter_asim.events import log_authentication
from .utils import has_valid_token, get_client
from . import types
from django.contrib.auth.signals import user_logged_out


def log_successful_login(request: HttpRequest, userinfo: types.UserInfo) -> None:
    target_user = userinfo.get("email") or "Unknown"
    log_authentication(
        request,
        event=log_authentication.Event.Logon,
        result=log_authentication.Result.Success,
        login_method=log_authentication.LoginMethod.UKGOVSSO,
        user={
            "username": target_user,
        },
    )


def log_failed_login(request: HttpRequest) -> None:
    log_authentication(
        request,
        event=log_authentication.Event.Logon,
        result=log_authentication.Result.Failure,
        login_method=log_authentication.LoginMethod.UKGOVSSO,
    )


def _logged_out_signal_handler(sender, request, user, **kwargs) -> None:
    # The "user session" doesn't store information on which authentication backend was used.
    # We can however, use the same `has_valid_token` mechanism to check the presence of a valid OAuth token.
    try:
        # As we don't know the authentication backend, we can't assume it's govuk-onelogin-django.
        # Therefore, silence any errors that can occur.
        valid_token = has_valid_token(get_client(request))
    except Exception:
        valid_token = False

    if valid_token:
        log_authentication(
            request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UKGOVSSO,
        )


def enable_logout_logging() -> None:
    user_logged_out.connect(_logged_out_signal_handler)
