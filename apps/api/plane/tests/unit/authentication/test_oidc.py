# SPDX-License-Identifier: AGPL-3.0-only
import time
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory

from plane.authentication.provider import oidc
from plane.authentication.views.app.oidc import OIDCCallbackEndpoint, OIDCInitiateEndpoint
from plane.db.models import Account

pytestmark = pytest.mark.unit
CONFIG = dict(
    issuer="https://id.example/application/o/plane/",
    client_id="plane",
    callback="https://plane.example/auth/oidc/callback/",
    group="plane-users",
    secret="test-secret",
)
DOCUMENT = dict(jwks_uri="https://id.example/jwks", authorization_endpoint="https://id.example/authorize")
VIEW = "plane.authentication.views.app.oidc."


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **updates):
    claims = dict(
        iss=CONFIG["issuer"],
        aud="plane",
        sub="stable-id",
        exp=time.time() + 120,
        iat=time.time(),
        nonce="nonce",
        groups=["plane-users"],
    )
    claims.update(updates)
    return jwt.encode(claims, key, algorithm="RS256")


def validate(key, encoded):
    with patch.object(oidc, "jwks_client") as client:
        client.return_value.get_signing_key_from_jwt.return_value.key = key.public_key()
        return oidc.validate_token(encoded, CONFIG, DOCUMENT, "nonce")


def test_valid_signature_and_claims(signing_key):
    assert validate(signing_key, token(signing_key))["sub"] == "stable-id"


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://evil.example"},
        {"aud": "different-client"},
        {"exp": time.time() - 120},
        {"iat": time.time() + 300},
        {"nonce": "different-nonce"},
        {"groups": []},
        {"groups": "plane-users"},
        {"sub": ""},
        {"aud": ["plane", "other"]},
        {"azp": "other"},
        {"at_hash": "invalid"},
    ],
)
def test_reject_invalid_claims(signing_key, changes):
    with pytest.raises((oidc.OIDCError, jwt.PyJWTError)):
        validate(signing_key, token(signing_key, **changes))


def test_reject_forged_signature(signing_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(jwt.InvalidSignatureError):
        validate(signing_key, token(other))


def test_reject_symmetric_algorithm(signing_key):
    with pytest.raises(jwt.InvalidAlgorithmError):
        validate(signing_key, jwt.encode({"sub": "stable-id"}, "a" * 32, algorithm="HS256"))


def test_pkce_rfc7636_vector():
    assert (
        oidc.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_issuer_namespaces_subject():
    assert oidc.account_id("https://a/", "same") != oidc.account_id("https://b/", "same")


class Session(dict):
    def set_expiry(self, value):
        self.expiry = value


def callback_request(**changes):
    request = RequestFactory().get("/auth/oidc/callback/", {"code": "code", "state": "state", **changes})
    request.session = Session(
        oidc_transaction=dict(
            state="state", nonce="nonce", verifier="verifier", started=time.time(), next_path="/workspace"
        )
    )
    return request


@pytest.mark.parametrize(
    "variant", ["missing_session", "missing_state", "wrong_state", "missing_code", "expired", "error"]
)
def test_callback_rejects_before_network(variant):
    request = callback_request(
        **{
            "missing_state": {"state": ""},
            "wrong_state": {"state": "evil"},
            "missing_code": {"code": ""},
            "error": {"error": "access_denied"},
        }.get(variant, {})
    )
    if variant == "missing_session":
        request.session.clear()
    if variant == "expired":
        request.session["oidc_transaction"]["started"] -= 301
    with patch(VIEW + "exchange") as exchange:
        assert OIDCCallbackEndpoint.as_view()(request).status_code == 403
        exchange.assert_not_called()
    assert "oidc_transaction" not in request.session


def test_disabled_oidc(monkeypatch):
    monkeypatch.delenv("OIDC_ENABLED", raising=False)
    assert OIDCInitiateEndpoint.as_view()(RequestFactory().get("/auth/oidc/")).status_code == 403


@pytest.mark.django_db
def test_explicit_link_is_idempotent_and_keeps_existing_user(create_user):
    kwargs = dict(user_id=str(create_user.id), issuer=CONFIG["issuer"], subject="stable-id")
    call_command("link_oidc_account", **kwargs)
    call_command("link_oidc_account", **kwargs)
    assert Account.objects.filter(provider="oidc").count() == 1
    assert Account.objects.get(provider="oidc").user_id == create_user.id


@pytest.mark.django_db
def test_link_refuses_reassignment(create_user):
    from plane.db.models import User

    other = User.objects.create(email="other@example.org", username="other-user")
    kwargs = dict(issuer=CONFIG["issuer"], subject="stable-id")
    call_command("link_oidc_account", user_id=str(create_user.id), **kwargs)
    with pytest.raises(CommandError):
        call_command("link_oidc_account", user_id=str(other.id), **kwargs)
    assert Account.objects.get(provider="oidc").user_id == create_user.id


@pytest.mark.django_db
@pytest.mark.parametrize("mode", ["linked", "unlinked", "inactive", "bot", "external_redirect"])
def test_callback_account_authorization(create_user, mode):
    if mode != "unlinked":
        call_command("link_oidc_account", user_id=str(create_user.id), issuer=CONFIG["issuer"], subject="stable-id")
    if mode in ("inactive", "bot"):
        if mode == "inactive":
            create_user.is_active = False
        else:
            create_user.is_bot = True
        create_user.save()
    request = callback_request()
    if mode == "external_redirect":
        request.session["oidc_transaction"]["next_path"] = "https://evil.example/steal"
    with (
        patch(VIEW + "configuration", return_value=CONFIG),
        patch(VIEW + "discovery", return_value=DOCUMENT),
        patch(VIEW + "exchange", return_value={"sub": "stable-id", "email": create_user.email}),
        patch(VIEW + "user_login") as login,
    ):
        response = OIDCCallbackEndpoint.as_view()(request)
        if mode in ("linked", "external_redirect"):
            assert response.status_code == 302
            assert response["Location"].startswith("https://plane.example/")
            login.assert_called_once_with(request=request, user=create_user, is_app=True)
            assert request.session.expiry == 3600
            # Replaying the same callback cannot establish another session.
            assert OIDCCallbackEndpoint.as_view()(request).status_code == 403
            assert login.call_count == 1
        else:
            assert response.status_code == 403
            login.assert_not_called()


def test_initiate_preserves_existing_session_until_callback():
    from urllib.parse import urlsplit, parse_qs

    request = RequestFactory().get("/auth/oidc/", {"next_path": "/workspace"})
    request.session = Session(_auth_user_id="existing-user")
    with (
        patch(VIEW + "configuration", return_value=CONFIG),
        patch(VIEW + "discovery", return_value=DOCUMENT),
        patch(VIEW + "Instance") as instance,
    ):
        instance.objects.filter.return_value.exists.return_value = True
        response = OIDCInitiateEndpoint.as_view()(request)
    assert response.status_code == 302
    assert request.session["_auth_user_id"] == "existing-user"
    transaction = request.session["oidc_transaction"]
    params = parse_qs(urlsplit(response["Location"]).query)
    assert params["state"] == [transaction["state"]]
    assert params["nonce"] == [transaction["nonce"]]
    assert params["code_challenge"] == [oidc.challenge(transaction["verifier"])]
    assert params["code_challenge_method"] == ["S256"]


def test_oidc_callback_query_not_logged():
    from types import SimpleNamespace
    from django.http import HttpResponse
    from plane.middleware.logger import RequestLoggerMiddleware

    request = RequestFactory().get("/auth/oidc/callback/", {"code": "secret-code", "state": "secret-state"})
    request.user = SimpleNamespace(is_authenticated=False)
    with patch("plane.middleware.logger.api_logger") as logger:
        RequestLoggerMiddleware(lambda r: HttpResponse(status=403))(request)
    logger.info.assert_called_once()
    logged = str(logger.info.call_args)
    assert "secret-code" not in logged and "secret-state" not in logged
    assert "/auth/oidc/callback/" in logged
