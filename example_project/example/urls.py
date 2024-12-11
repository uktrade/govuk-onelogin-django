"""
URL configuration for example project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
"""

from django.urls import include, path

from .views import ExampleLoginRequiredView, ExampleLogoutView, OneLoginExampleView

urlpatterns = [
    # Include the govuk_onelogin_django urls
    path("one-login/", include("govuk_onelogin_django.urls")),
    # Example views.
    path("", OneLoginExampleView.as_view(), name="login-start"),
    path("logged-in-view/", ExampleLoginRequiredView.as_view(), name="logged_in_view"),
    path("logout/", ExampleLogoutView.as_view(), name="logout"),
]
