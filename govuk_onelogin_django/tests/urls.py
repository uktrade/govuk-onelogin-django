from django.urls import include, path

# urls.py used when running tests (only way to get reverse() to work with one_login namespace)
urlpatterns = [
    # Include the govuk_onelogin_django urls
    path("one-login/", include("govuk_onelogin_django.urls")),
]
