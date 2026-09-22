import pytest


@pytest.fixture()
def example_token():
    return {
        "access_token": (
            "eyJraWQiOiJmOTJmOWY4M2QzNWE1MzMxMTcwNzk3MzI3MWMxMWE2YTEyZDg2OWU4ZTNiZDczMTQ0NTQyOTJiOGQ4"
            "ZDRiODlmIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOkF2dHV4TzE5YXJEUXdXT"
            "mN2OUhMUTB5M09tMG5xS2tqNlA1MElJRjlid00iLCJzY29wZSI6WyJvcGVuaWQiLCJlbWFpbCJdLCJpc3MiOiJod"
            "HRwczovL29pZGMuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsvIiwiZXhwIjoxNzkwMDg5OTUxLCJpYXQiOjE3O"
            "TAwODk3NzEsImNsaWVudF9pZCI6IncwU0cwUzhQSi00dmRlVy1OYW1relVzLURhQSIsImp0aSI6IjNmZGNhOTE0L"
            "TJiZmUtNGI3Yi1hZDEwLWJlNGY5ZjZhNWQ2MSIsInNpZCI6IjF0NXVWcElRcExqYVF4QWNFNUU4Qk9fMmgxZyJ9."
            "rBDGjDHWaHpdZauVxxBa7KDq5LeUj1Hc11I7vw3Tk_nU8F4tf2GcSLC8krII0pk8RU1cKpOVT3_ZckdKxWepkQ"
        ),
        "id_token": (
            "eyJraWQiOiJmOTJmOWY4M2QzNWE1MzMxMTcwNzk3MzI3MWMxMWE2YTEyZDg2OWU4ZTNiZDczMTQ0NTQyOTJiOGQ4"
            "ZDRiODlmIiwiYWxnIjoiRVMyNTYifQ.eyJhdF9oYXNoIjoiZl92a2VocTdfME5vUVZyNnltcXBnZyIsInN1YiI6I"
            "nVybjpmZGM6Z292LnVrOjIwMjI6QXZ0dXhPMTlhckRRd1dOY3Y5SExRMHkzT20wbnFLa2o2UDUwSUlGOWJ3TSIsI"
            "mF1ZCI6IncwU0cwUzhQSi00dmRlVy1OYW1relVzLURhQSIsImF1dGhfdGltZSI6MTc5MDA4OTY3NSwiaXNzIjoia"
            "HR0cHM6Ly9vaWRjLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrLyIsInZvdCI6IkNsIiwiZXhwIjoxNzkwMDg5O"
            "DkxLCJpYXQiOjE3OTAwODk3NzEsIm5vbmNlIjoiYk0zVUczakZxNUxNZ0V3V2h6RENBVllyOXR6OGQ1IiwidnRtI"
            "joiaHR0cHM6Ly9vaWRjLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrL3RydXN0bWFyayIsInNpZCI6IjF0NXVWc"
            "ElRcExqYVF4QWNFNUU4Qk9fMmgxZyJ9.di3BOmFX5P2vjEyHo75dAlaSIYiaQjo0IZdnBpdTQK-Usv1JLBMXgznM"
            "wcvXhGi0NtwBDpyTOho_DOADBQp_HA"
        ),
        "token_type": "Bearer",
        "expires_in": 180,
        "expires_at": 1790089951,
    }


@pytest.fixture()
def example_public_keys():
    return [
        {
            "kty": "EC",
            "use": "sig",
            "crv": "P-256",
            "kid": "f92f9f83d35a53311707973271c11a6a12d869e8e3bd7314454292b8d8d4b89f",
            "x": "rRZZWFw18Rk44QQwSV1c9J3j-nR1UEDiSWJ5lm3Q02M",
            "y": "Tu3-5xWQcacuBa8fnY6ZAMwkskfJyuV0-4I68F4zvXs",
            "alg": "ES256",
        },
    ]
