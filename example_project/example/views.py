from django.conf import settings
from django.contrib import auth
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import RedirectView, TemplateView

from govuk_onelogin_django.utils import get_one_login_logout_url


class OneLoginExampleView(TemplateView):
    template_name = "example.html"


class ExampleLoginRequiredView(LoginRequiredMixin, TemplateView):
    template_name = "logged-in-view.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context | {
            "has_usable_password": self.request.user.has_usable_password(),
        }


class ExampleLogoutView(LoginRequiredMixin, RedirectView):
    http_method_names = ["post"]
    redirect_url: str

    def post(self, request, *args, **kwargs):
        # 1. Set the correct post logout redirect URI
        # URL to redirect a user back to after logging out of GOV.UK One login
        post_logout_redirect_uri = self.request.build_absolute_uri(
            reverse(settings.LOGIN_URL)
        )

        # Needs to be saved before auth.logout to use the session.
        self.redirect_url = get_one_login_logout_url(
            self.request, post_logout_redirect_uri
        )

        # 2. Clear session and user
        auth.logout(request)

        # 3. Redirect to GOV.UK One Login logout url.
        return super().post(request, *args, **kwargs)

    def get_redirect_url(
        self, *args, post_logout_redirect_uri: str | None = None, **kwargs
    ):
        return self.redirect_url
