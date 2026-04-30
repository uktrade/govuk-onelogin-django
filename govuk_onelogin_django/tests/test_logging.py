from unittest import mock
import json
from govuk_onelogin_django.logging import enable_logout_logging
from django.contrib.auth.signals import user_logged_out


@mock.patch("govuk_onelogin_django.logging.get_client", mock.Mock())
@mock.patch("govuk_onelogin_django.logging.has_valid_token")
def test_emits_logs_on_logout_with_valid_token(mocked_has_valid_token, rf, capsys):
    mocked_has_valid_token.return_value = True
    enable_logout_logging()
    user_logged_out.send(sender=None, request=rf.get("/"), user=None)
    assert_event_logged(capsys, "Logoff", "Success")


@mock.patch("govuk_onelogin_django.logging.get_client", mock.Mock())
@mock.patch("govuk_onelogin_django.logging.has_valid_token")
def test_does_not_emit_logs_on_logout_without_valid_token(
    mocked_has_valid_token, rf, capsys
):
    mocked_has_valid_token.return_value = False
    enable_logout_logging()
    user_logged_out.send(sender=None, request=rf.get("/"), user=None)

    assert_no_logs_generated(capsys)


def assert_event_logged(capsys, type, result, username=None):
    (out, _) = capsys.readouterr()
    event = json.loads(out)

    assert event["EventType"] == type
    assert event["EventResult"] == result
    if username is None:
        assert "TargetUsername" not in event
    else:
        assert event["TargetUsername"] == username
    assert event["LogonMethod"] == "UK.GOV-SSO"


def assert_no_logs_generated(capsys):
    (out, _) = capsys.readouterr()

    assert out == ""
