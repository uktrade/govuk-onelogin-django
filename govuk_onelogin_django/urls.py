from django.conf import settings
from django.urls import path

from .views import AuthCallbackView, AuthView, OIDCBackChannelLogoutView

app_name = "one_login"
urlpatterns = [
    path("login/", AuthView.as_view(), name="login"),
    path("callback/", AuthCallbackView.as_view(), name="callback"),
]

if getattr(settings, "GOV_UK_ONE_LOGIN_BACK_CHANNEL_ENABLED", True):
    urlpatterns += [
        path(
            "back-channel-logout/",
            OIDCBackChannelLogoutView.as_view(),
            name="back-channel-logout",
        )
    ]
